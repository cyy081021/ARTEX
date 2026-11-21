package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Native Campaign v1 (T4a) bounded runner protocol.
//
// This file contains only the internal Go contract and fake-runner support
// types. It does not start Python, Docker, AFL, GDB or any external target. The
// real campaign runner and the external registration are explicitly out of
// scope for T4a.
const (
	// NativeCampaignMaxFinalJSON is the hard cap for one final frame payload.
	NativeCampaignMaxFinalJSON = 256 << 10
	// NativeCampaignMaxEvidenceTotal is the total evidence bytes the Go side will
	// accept from one attempt (events + final). It is independent of the old
	// 3 MiB native_session envelope.
	NativeCampaignMaxEvidenceTotal = 8 << 20
	// NativeCampaignMaxFrameBytes bounds a single protocol line. It matches the
	// existing Python protocol 1 MiB frame limit.
	NativeCampaignMaxFrameBytes = 1 << 20
	// NativeCampaignMaxCheckpointEntries matches the T3 manifest/checkpoint limit.
	NativeCampaignMaxCheckpointEntries = 512
	// NativeCampaignMaxObjectBytes matches the T3 object limit.
	NativeCampaignMaxObjectBytes = 4096
	// NativeCampaignMaxSeeds and NativeCampaignMaxSeedBytes match section 8.3.
	NativeCampaignMaxSeeds     = 32
	NativeCampaignMaxSeedBytes = 65536
)

var (
	errNativeCampaignProtocolViolation = errors.New("native campaign runner protocol violation")
	errNativeCampaignEvidenceLimit     = errors.New("native campaign evidence exceeds 8 MiB")
	errNativeCampaignFinalLimit        = errors.New("native campaign final JSON exceeds 256 KiB")
)

// nativeCampaignRunner is the injectable runner boundary. Start must not create
// resources before the manager has persisted started_at/owned_resources via the
// fenced DB CAS. Control is idempotent per request_id. Events may close only
// when Wait will return (normal or error); an early close is treated as EOF and
// cancels the attempt. Cleanup is a cleanup probe: it must never execute the
// target or start a new container.
type nativeCampaignRunner interface {
	Start(ctx context.Context, start nativeCampaignRunnerStart) error
	Control(ctx context.Context, control nativeCampaignRunnerControl) error
	Events() <-chan nativeCampaignRunnerEvent
	Wait(ctx context.Context) (nativeCampaignRunnerFinal, error)
	Cleanup(ctx context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error)
}

type nativeCampaignRunnerFactory func(ctx context.Context, start nativeCampaignRunnerStart) (nativeCampaignRunner, error)

type nativeCampaignSeed struct {
	SHA256     string `json:"sha256"`
	DataBase64 string `json:"data_base64"`
	SourceType string `json:"source_type,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
}

type nativeCampaignRunnerProfile struct {
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	FuzzEnabled  bool   `json:"fuzz_enabled"`
	Enabled      bool   `json:"enabled"`
	Network      string `json:"network"`
	ReadOnlyRoot bool   `json:"read_only_root"`
	MaxDuration  int64  `json:"max_duration_ms"`
}

// nativeCampaignRunnerStart is the normalized start frame. Deadlines are
// absolute and established once from attempt.started_at; heartbeats and resumes
// of the same attempt must never move them.
type nativeCampaignRunnerStart struct {
	TaskID               int64                       `json:"task_id"`
	RequestID            string                      `json:"request_id"`
	CampaignID           int64                       `json:"campaign_id"`
	AttemptID            int64                       `json:"attempt_id"`
	AttemptNo            int                         `json:"attempt_no"`
	FencingToken         int64                       `json:"fencing_token"`
	LeaseOwner           string                      `json:"lease_owner"`
	LeaseInstance        string                      `json:"lease_instance"`
	LeaseMS              int64                       `json:"lease_ms"`
	LeaseDeadline        string                      `json:"lease_deadline"`
	ArtifactPath         string                      `json:"artifact_path"`
	SHA256               string                      `json:"sha256"`
	Argv                 []string                    `json:"argv"`
	InputMode            string                      `json:"input_mode"`
	Seeds                []nativeCampaignSeed        `json:"seeds"`
	MaxExecutions        int                         `json:"max_executions"`
	MaxCrashes           int                         `json:"max_crashes"`
	AttemptBudgetMS      int64                       `json:"attempt_budget_ms"`
	ExecutionWindowMS    int64                       `json:"execution_window_ms"`
	ExecutionDeadline    string                      `json:"execution_deadline"`
	EnvelopeDeadline     string                      `json:"envelope_deadline"`
	CleanupReserveMS     int64                       `json:"cleanup_reserve_ms"`
	CleanupHardTimeoutMS int64                       `json:"cleanup_hard_timeout_ms"`
	Profile              nativeCampaignRunnerProfile `json:"profile"`
	OwnedResources       json.RawMessage             `json:"owned_resources"`
}

// Validate checks the bounded start frame before a runner factory is invoked.
func (s nativeCampaignRunnerStart) Validate() error {
	if s.TaskID <= 0 || s.CampaignID <= 0 || s.AttemptID <= 0 || s.AttemptNo < 1 {
		return fmt.Errorf("%w: start frame identity is incomplete", errNativeCampaignProtocolViolation)
	}
	if strings.TrimSpace(s.RequestID) == "" || len(s.RequestID) > 128 {
		return fmt.Errorf("%w: invalid request_id", errNativeCampaignProtocolViolation)
	}
	if s.FencingToken <= 0 || s.LeaseMS < 1000 || s.LeaseMS > 120000 {
		return fmt.Errorf("%w: invalid fence or lease_ms", errNativeCampaignProtocolViolation)
	}
	if s.AttemptBudgetMS < 6000 || s.AttemptBudgetMS > 900000 {
		return fmt.Errorf("%w: invalid attempt budget", errNativeCampaignProtocolViolation)
	}
	if s.ExecutionWindowMS < 1000 || s.ExecutionWindowMS > s.AttemptBudgetMS-5000 {
		return fmt.Errorf("%w: invalid execution window", errNativeCampaignProtocolViolation)
	}
	if s.ExecutionDeadline == "" || s.EnvelopeDeadline == "" || s.LeaseDeadline == "" {
		return fmt.Errorf("%w: absolute deadlines are required", errNativeCampaignProtocolViolation)
	}
	lease, leaseErr := time.Parse(time.RFC3339Nano, s.LeaseDeadline)
	execution, executionErr := time.Parse(time.RFC3339Nano, s.ExecutionDeadline)
	if leaseErr != nil || executionErr != nil || lease.After(execution) {
		return fmt.Errorf("%w: invalid absolute lease deadline", errNativeCampaignProtocolViolation)
	}
	if s.CleanupReserveMS < 0 || s.CleanupReserveMS > 60000 {
		return fmt.Errorf("%w: invalid cleanup reserve", errNativeCampaignProtocolViolation)
	}
	if s.InputMode != "stdin" && s.InputMode != "file" {
		return fmt.Errorf("%w: input_mode must be stdin or file", errNativeCampaignProtocolViolation)
	}
	if len(s.Argv) > 64 {
		return fmt.Errorf("%w: too many argv entries", errNativeCampaignProtocolViolation)
	}
	for _, a := range s.Argv {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return fmt.Errorf("%w: invalid argv entry", errNativeCampaignProtocolViolation)
		}
	}
	if err := validateNativeCampaignSeeds(s.Seeds); err != nil {
		return err
	}
	if !db.NativeImageDigest(s.Profile.Image) || s.Profile.ImageID == "" {
		return fmt.Errorf("%w: immutable image and resolved image_id are required", errNativeCampaignProtocolViolation)
	}
	if !s.Profile.Enabled || !s.Profile.FuzzEnabled {
		return fmt.Errorf("%w: profile is not enabled for fuzzing", errNativeCampaignProtocolViolation)
	}
	if s.Profile.Network != "" && s.Profile.Network != "none" {
		return fmt.Errorf("%w: campaign profile must not request a network", errNativeCampaignProtocolViolation)
	}
	if !s.Profile.ReadOnlyRoot {
		return fmt.Errorf("%w: campaign root filesystem must be read-only", errNativeCampaignProtocolViolation)
	}
	plan, err := nativeCampaignPlanFromResources(s.OwnedResources)
	if err != nil {
		return fmt.Errorf("%w: invalid resource plan: %v", errNativeCampaignProtocolViolation, err)
	}
	if err = plan.validate(s.TaskID, s.CampaignID, s.AttemptID, s.FencingToken); err != nil {
		return fmt.Errorf("%w: %v", errNativeCampaignProtocolViolation, err)
	}
	if len(s.OwnedResources) > 16384 {
		return fmt.Errorf("%w: owned_resources is too large", errNativeCampaignProtocolViolation)
	}
	return nil
}

type nativeCampaignRunnerControl struct {
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Reason    string `json:"reason,omitempty"`
	// LeaseMS is a requested TTL bound, not a receipt-relative renewal.
	// LeaseDeadline is the sole authoritative runner lease cutoff.
	LeaseMS       int64  `json:"lease_ms,omitempty"`
	LeaseDeadline string `json:"lease_deadline,omitempty"`
}

func (c nativeCampaignRunnerControl) Validate() error {
	if strings.TrimSpace(c.RequestID) == "" || len(c.RequestID) > 128 {
		return fmt.Errorf("%w: invalid control request_id", errNativeCampaignProtocolViolation)
	}
	switch c.Action {
	case "pause", "cancel", "status", "heartbeat":
	default:
		return fmt.Errorf("%w: unknown control action %q", errNativeCampaignProtocolViolation, c.Action)
	}
	if len(c.Reason) > 512 || strings.ContainsRune(c.Reason, 0) {
		return fmt.Errorf("%w: invalid control reason", errNativeCampaignProtocolViolation)
	}
	if c.Action == "heartbeat" {
		if c.LeaseMS < 1000 || c.LeaseMS > 120000 {
			return fmt.Errorf("%w: heartbeat lease_ms is outside 1000..120000", errNativeCampaignProtocolViolation)
		}
		if _, err := time.Parse(time.RFC3339Nano, c.LeaseDeadline); err != nil {
			return fmt.Errorf("%w: heartbeat requires absolute lease_deadline", errNativeCampaignProtocolViolation)
		}
	} else if c.LeaseMS != 0 || c.LeaseDeadline != "" {
		return fmt.Errorf("%w: lease_ms is only allowed on heartbeat", errNativeCampaignProtocolViolation)
	}
	return nil
}

// cancelWins is the only allowed pause/cancel ordering. A pause already sent is
// upgraded by cancel; a cancel is never downgraded to pause.
func cancelWins(current, next string) string {
	if current == "cancel" || next == "cancel" {
		return "cancel"
	}
	if next == "pause" || current == "pause" {
		return "pause"
	}
	return ""
}

type nativeCampaignRunnerEvent struct {
	RequestID    string          `json:"request_id"`
	AttemptID    int64           `json:"attempt_id,omitempty"`
	FencingToken int64           `json:"fencing_token,omitempty"`
	Kind         string          `json:"kind"`
	Observation  json.RawMessage `json:"observation"`
}

func (e nativeCampaignRunnerEvent) Validate(expect nativeCampaignFrameExpectation) error {
	if e.RequestID != expect.RequestID {
		return fmt.Errorf("%w: event request_id does not match", errNativeCampaignProtocolViolation)
	}
	if e.AttemptID != 0 && e.AttemptID != expect.AttemptID {
		return fmt.Errorf("%w: event attempt_id does not match", errNativeCampaignProtocolViolation)
	}
	if e.FencingToken != 0 && e.FencingToken != expect.FencingToken {
		return fmt.Errorf("%w: event fencing token does not match", errNativeCampaignProtocolViolation)
	}
	switch e.Kind {
	case "event", "result", "phase", "checkpoint_chunk":
	default:
		return fmt.Errorf("%w: unknown event kind %q", errNativeCampaignProtocolViolation, e.Kind)
	}
	if len(e.Observation) == 0 || !json.Valid(e.Observation) {
		return fmt.Errorf("%w: event observation must be valid JSON", errNativeCampaignProtocolViolation)
	}
	if len(e.Observation) > NativeCampaignMaxFrameBytes {
		return fmt.Errorf("%w: event frame exceeds 1 MiB", errNativeCampaignProtocolViolation)
	}
	return nil
}

type nativeCampaignRunnerManifest struct {
	Engine          string `json:"engine"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	Image           string `json:"image"`
	ImageID         string `json:"image_id"`
	InputMode       string `json:"input_mode"`
	AFLVersion      string `json:"afl_version"`
	ShowmapVersion  string `json:"showmap_version"`
	OptionsVerified bool   `json:"options_verified"`
	ProbeEdges      int    `json:"probe_edges"`
	ProbeExecutions int    `json:"probe_executions"`
	OutputDiskLimit int64  `json:"output_disk_limit_bytes"`
	SingleWorker    bool   `json:"single_worker"`
}

type nativeCampaignRunnerCleanup struct {
	OwnedProcessTerminated bool `json:"owned_process_terminated"`
	ContainerRemoved       bool `json:"container_removed"`
	StagingRemoved         bool `json:"staging_removed"`
}

func (c nativeCampaignRunnerCleanup) verified() bool {
	return c.OwnedProcessTerminated && c.ContainerRemoved && c.StagingRemoved
}

type nativeCampaignRunnerBudget struct {
	ReservedMS           int64 `json:"reserved_ms"`
	ChargedMS            int64 `json:"charged_ms"`
	ActualElapsedMS      int64 `json:"actual_elapsed_ms"`
	CleanupOverrunMS     int64 `json:"cleanup_overrun_ms"`
	ObservedExecs        int64 `json:"observed_execs"`
	ObservedExecsTrusted bool  `json:"observed_execs_trusted"`
	BudgetOverrun        bool  `json:"budget_overrun"`
}

type nativeCampaignRunnerCheckpoint struct {
	FormatVersion  int    `json:"format_version"`
	EntryCount     int    `json:"entry_count"`
	TotalBytes     int64  `json:"total_bytes"`
	Truncated      bool   `json:"truncated"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type nativeCampaignRunnerFinal struct {
	CreationSeal *nativeCampaignCreationSeal `json:"creation_seal,omitempty"`
	// Local verified handoff only. This field cannot be supplied by the wire.
	CheckpointCorpus []nativeCampaignCheckpointRecord `json:"-"`
	RequestID        string                           `json:"request_id"`
	TaskID           int64                            `json:"task_id"`
	CampaignID       int64                            `json:"campaign_id"`
	AttemptID        int64                            `json:"attempt_id"`
	FencingToken     int64                            `json:"fencing_token"`
	TargetState      string                           `json:"target_state"`
	Phase            string                           `json:"phase"`
	Manifest         nativeCampaignRunnerManifest     `json:"manifest"`
	Stats            map[string]any                   `json:"stats"`
	Cleanup          nativeCampaignRunnerCleanup      `json:"cleanup"`
	CleanupVerified  bool                             `json:"cleanup_verified"`
	CleanupHold      struct {
		ResourceHold bool   `json:"resource_hold"`
		HoldReason   string `json:"hold_reason"`
	} `json:"cleanup_hold"`
	Checkpoint *nativeCampaignRunnerCheckpoint `json:"checkpoint,omitempty"`
	Budget     nativeCampaignRunnerBudget      `json:"budget"`
	Errors     []string                        `json:"errors"`
	Truncated  bool                            `json:"truncated"`
	Limited    bool                            `json:"limited"`
	Reason     string                          `json:"reason"`
	Candidate  bool                            `json:"candidate_only"`
	Authority  string                          `json:"authority"`
}

// Validate enforces the bounded final contract and the fence/identity binding.
// observed_execs_trusted=true is rejected: runner-reported execution counts are
// display-only and can never be accounting evidence.
func (f nativeCampaignRunnerFinal) Validate(expect nativeCampaignFrameExpectation) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w: final cannot be encoded", errNativeCampaignProtocolViolation)
	}
	if len(raw) > NativeCampaignMaxFinalJSON {
		return errNativeCampaignFinalLimit
	}
	if f.RequestID != expect.RequestID || f.TaskID != expect.TaskID ||
		f.CampaignID != expect.CampaignID || f.AttemptID != expect.AttemptID ||
		f.FencingToken != expect.FencingToken {
		return fmt.Errorf("%w: final identity/fence does not match the active attempt", errNativeCampaignProtocolViolation)
	}
	switch f.TargetState {
	case "completed", "failed", "cancelled", "paused", "interrupted", "timeout":
	default:
		return fmt.Errorf("%w: unknown final target_state %q", errNativeCampaignProtocolViolation, f.TargetState)
	}
	if f.Cleanup.verified() != f.CleanupVerified {
		return fmt.Errorf("%w: cleanup_verified does not match the cleanup triple", errNativeCampaignProtocolViolation)
	}
	if f.CleanupHold.ResourceHold && f.CleanupVerified {
		return fmt.Errorf("%w: verified cleanup cannot keep a resource hold", errNativeCampaignProtocolViolation)
	}
	if f.Budget.ObservedExecsTrusted {
		return fmt.Errorf("%w: observed_execs cannot be trusted/billable", errNativeCampaignProtocolViolation)
	}
	if len(f.Errors) > 32 {
		return fmt.Errorf("%w: too many final errors", errNativeCampaignProtocolViolation)
	}
	for _, e := range f.Errors {
		if len(e) > 512 {
			return fmt.Errorf("%w: final error is too long", errNativeCampaignProtocolViolation)
		}
	}
	if len(f.Reason) > 512 {
		return fmt.Errorf("%w: final reason is too long", errNativeCampaignProtocolViolation)
	}
	if f.Authority != "" && f.Authority != "candidate-only" {
		return fmt.Errorf("%w: campaign authority must be candidate-only", errNativeCampaignProtocolViolation)
	}
	if f.Checkpoint != nil {
		if f.Checkpoint.FormatVersion != 1 ||
			f.Checkpoint.EntryCount < 1 || f.Checkpoint.EntryCount > NativeCampaignMaxCheckpointEntries ||
			f.Checkpoint.TotalBytes < 1 || f.Checkpoint.TotalBytes > 1<<20 ||
			!db.NativeSHA256(f.Checkpoint.ManifestSHA256) {
			return fmt.Errorf("%w: invalid checkpoint summary", errNativeCampaignProtocolViolation)
		}
	}
	if f.TargetState == "paused" && f.Checkpoint == nil {
		return fmt.Errorf("%w: paused final requires a checkpoint summary", errNativeCampaignProtocolViolation)
	}
	return nil
}

type nativeCampaignCleanupRequest struct {
	ResourcePlan *nativeCampaignResourcePlan `json:"resource_plan,omitempty"`
	CreationSeal *nativeCampaignCreationSeal `json:"creation_seal,omitempty"`
	RequestID    string                      `json:"request_id"`
	TaskID       int64                       `json:"task_id"`
	CampaignID   int64                       `json:"campaign_id"`
	AttemptID    int64                       `json:"attempt_id"`
	FencingToken int64                       `json:"fencing_token"`
}

type nativeCampaignCleanupContainer struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	State       string `json:"state"`
	LabelsMatch bool   `json:"labels_match"`
}

type nativeCampaignCleanupReport struct {
	PlanSHA256      string                           `json:"plan_sha256,omitempty"`
	StagingBasename string                           `json:"staging_basename,omitempty"`
	CleanupVerified bool                             `json:"cleanup_verified"`
	Containers      []nativeCampaignCleanupContainer `json:"containers"`
	Staging         struct {
		Present bool `json:"present"`
		Removed bool `json:"removed"`
	} `json:"staging"`
	Errors      []string `json:"errors"`
	HardTimeout bool     `json:"hard_timeout"`
	ElapsedMS   int64    `json:"elapsed_ms"`
}

func (r nativeCampaignCleanupReport) verified() bool {
	// A verified report requires the probe's own affirmative verdict, no hard
	// timeout, no errors, absent+removed staging, and at least one confirmed
	// absent/removed container whose labels identity matched. Unknown states,
	// label mismatches, remaining containers, empty/missing identity evidence
	// and any error can never be promoted to verified. There is deliberately no
	// name-based compatibility list: test fixture names have no production
	// privilege.
	if !r.CleanupVerified || r.HardTimeout || len(r.Errors) > 0 {
		return false
	}
	if r.Staging.Present || !r.Staging.Removed {
		return false
	}
	if len(r.Containers) == 0 {
		return false
	}
	for _, c := range r.Containers {
		if strings.TrimSpace(c.Name) == "" || len(c.Name) > 256 {
			return false
		}
		if c.State != "absent" && c.State != "removed" {
			return false
		}
		if !c.LabelsMatch {
			return false
		}
	}
	return true
}

type nativeCampaignFrameExpectation struct {
	RequestID    string
	TaskID       int64
	CampaignID   int64
	AttemptID    int64
	FencingToken int64
}

// nativeCampaignFrameReader is a bounded, persistent line reader. One reader
// must be reused for the whole runner stream: constructing a new Scanner per
// frame can consume and discard the next line from the shared io.Reader.
type nativeCampaignFrameReader struct {
	r   *bufio.Reader
	max int
}

func newNativeCampaignFrameReader(r io.Reader) *nativeCampaignFrameReader {
	return &nativeCampaignFrameReader{r: bufio.NewReaderSize(r, 64<<10), max: NativeCampaignMaxFrameBytes}
}

func (f *nativeCampaignFrameReader) readLine() ([]byte, error) {
	var line []byte
	for {
		part, err := f.r.ReadSlice('\n')
		if len(line)+len(part) > f.max {
			return nil, fmt.Errorf("%w: frame exceeds 1 MiB", errNativeCampaignProtocolViolation)
		}
		line = append(line, part...)
		switch {
		case err == nil:
			line = bytes.TrimSuffix(line, []byte("\n"))
			line = bytes.TrimSuffix(line, []byte("\r"))
			return line, nil
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF:
			if len(line) == 0 {
				return nil, io.EOF
			}
			return line, nil
		default:
			return nil, fmt.Errorf("%w: read frame: %v", errNativeCampaignProtocolViolation, err)
		}
	}
}

// ReadFrame validates one bounded frame. Bad JSON, trailing garbage, multiple
// JSON objects, an unknown kind or a mismatched identity is a protocol
// violation; EOF is returned unchanged so the caller can treat it as a safe
// cancel. The reader keeps any pre-read bytes for the next call.
func (f *nativeCampaignFrameReader) ReadFrame(expect nativeCampaignFrameExpectation) (*nativeCampaignRunnerEvent, error) {
	line, err := f.readLine()
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var frame struct {
		RequestID    string          `json:"request_id"`
		TaskID       int64           `json:"task_id,omitempty"`
		CampaignID   int64           `json:"campaign_id,omitempty"`
		AttemptID    int64           `json:"attempt_id,omitempty"`
		FencingToken int64           `json:"fencing_token,omitempty"`
		Kind         string          `json:"kind"`
		Observation  json.RawMessage `json:"observation"`
	}
	if err := dec.Decode(&frame); err != nil {
		return nil, fmt.Errorf("%w: invalid frame JSON: %v", errNativeCampaignProtocolViolation, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%w: frame has trailing JSON data", errNativeCampaignProtocolViolation)
	}
	if frame.TaskID != 0 && frame.TaskID != expect.TaskID {
		return nil, fmt.Errorf("%w: frame task_id does not match", errNativeCampaignProtocolViolation)
	}
	if frame.CampaignID != 0 && frame.CampaignID != expect.CampaignID {
		return nil, fmt.Errorf("%w: frame campaign_id does not match", errNativeCampaignProtocolViolation)
	}
	ev := nativeCampaignRunnerEvent{
		RequestID: frame.RequestID, AttemptID: frame.AttemptID,
		FencingToken: frame.FencingToken, Kind: frame.Kind, Observation: frame.Observation,
	}
	if err := ev.Validate(expect); err != nil {
		return nil, err
	}
	return &ev, nil
}

// nativeCampaignEvidenceBudget implements the 8 MiB total evidence cap without
// affecting the legacy session envelope.
type nativeCampaignEvidenceBudget struct {
	total int64
}

func (b *nativeCampaignEvidenceBudget) Add(n int) error {
	if n < 0 {
		return errNativeCampaignProtocolViolation
	}
	if b.total+int64(n) > NativeCampaignMaxEvidenceTotal {
		return errNativeCampaignEvidenceLimit
	}
	b.total += int64(n)
	return nil
}

func (b *nativeCampaignEvidenceBudget) Total() int64 { return b.total }

// Shared pure validation; HTTP separately requires a nonempty initial corpus.
func validateNativeCampaignSeeds(seeds []nativeCampaignSeed) error {
	total := 0
	for _, seed := range seeds {
		if !db.NativeSHA256(seed.SHA256) {
			return fmt.Errorf("%w: invalid seed sha256", errNativeCampaignProtocolViolation)
		}
		data, err := base64.StdEncoding.Strict().DecodeString(seed.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(data) != seed.DataBase64 {
			return fmt.Errorf("%w: seed is not canonical base64", errNativeCampaignProtocolViolation)
		}
		if len(data) < 1 || len(data) > NativeCampaignMaxObjectBytes {
			return fmt.Errorf("%w: seed is empty or too large", errNativeCampaignProtocolViolation)
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != seed.SHA256 {
			return fmt.Errorf("%w: seed sha256 does not match its bytes", errNativeCampaignProtocolViolation)
		}
		total += len(data)
	}
	if len(seeds) > NativeCampaignMaxSeeds || total > NativeCampaignMaxSeedBytes {
		return fmt.Errorf("%w: too many seed bytes", errNativeCampaignProtocolViolation)
	}
	return nil
}
