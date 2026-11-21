package server

// Native Campaign v1 (T4b-1) bounded subprocess transport.
//
// The factory only constructs a transport. A subprocess exists only after
// Start. The command is a fixed configured interpreter/module (or an injected
// synthetic helper in tests); it is never a shell and never a user-supplied
// command line. The environment is an explicit minimal allowlist, never the
// parent's environment.
//
// This file deliberately has no manager/server/registration wiring, no Docker,
// AFL, GDB or real backend. T5 checkpoint persistence is also out of scope.

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
	"github.com/Autumn-27/artex/db"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	nativeCampaignDefaultPython = "/usr/bin/python3"
	nativeCampaignDefaultModule = "scripts.native_runner.main"

	nativeCampaignProcessQueue        = 32
	nativeCampaignControlPendingMax   = 32
	nativeCampaignControlLedgerMax    = 4096 // bounded attempt-lifetime control ledger
	nativeCampaignControlAbandonedMax = 64
	// nativeCampaignTailDrain is the explicit cap for delivering buffered tail
	// frames after a natural process exit. It is additionally clamped by the
	// common execution deadline.
	nativeCampaignTailDrain            = 2 * time.Second
	nativeCampaignStderrMax            = 64 << 10
	nativeCampaignEventQueue           = 64
	nativeCampaignCancelGrace          = 2 * time.Second
	nativeCampaignKillWait             = 2 * time.Second
	nativeCampaignControlWriteTimeout  = 500 * time.Millisecond
	nativeCampaignCheckpointChunkLimit = 64
	nativeCampaignCheckpointPartBytes  = 512 << 10
)

var (
	errNativeCampaignProcessStopped      = errors.New("native campaign process transport stopped")
	errNativeCampaignProcessDeadline     = errors.New("native campaign process deadline exceeded")
	errNativeCampaignProcessLeaseExpired = errors.New("native campaign process lease expired")
	errNativeCampaignProcessAbnormalExit = errors.New("native campaign process exited abnormally")
	errNativeCampaignProcessUnreaped     = errors.New("native campaign process completion was not confirmed")
	errNativeCampaignProcessTailDrain    = errors.New("native campaign tail drain deadline exceeded")
)

// nativeCampaignProcessConfig is the explicit process boundary. Command is the
// fixed interpreter+module argv prefix; tests replace it with a synthetic helper
// Python script. Starter overrides process creation only for deterministic
// tests. Env nil means the built-in minimal allowlist; a non-nil Env is used
// verbatim (still never merged with the parent environment).
type nativeCampaignProcessConfig struct {
	Command []string
	Dir     string
	Env     []string
	Starter nativeCampaignProcessStarter
}

type nativeCampaignProcessStarter func(spec nativeCampaignProcessSpec) (nativeCampaignProcessHandle, error)

type nativeCampaignProcessSpec struct {
	Argv []string
	Dir  string
	Env  []string
}

type nativeCampaignProcessHandle interface {
	Stdin() io.WriteCloser
	Stdout() io.ReadCloser
	Stderr() io.ReadCloser
	Wait() error
	Kill() error
	Close() error
}

func nativeCampaignProcessDefaultEnv() []string {
	return []string{
		"PATH=/usr/bin:/bin",
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PYTHONDONTWRITEBYTECODE=1",
		"PYTHONHASHSEED=0",
	}
}

func (c nativeCampaignProcessConfig) normalized() nativeCampaignProcessConfig {
	if len(c.Command) == 0 {
		c.Command = []string{nativeCampaignDefaultPython, "-B", "-m", nativeCampaignDefaultModule}
	}
	if c.Env == nil {
		c.Env = nativeCampaignProcessDefaultEnv()
	}
	if c.Starter == nil {
		c.Starter = defaultNativeCampaignProcessStarter
	}
	return c
}

type execNativeCampaignProcess struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	closeMu sync.Once
}

func (h *execNativeCampaignProcess) Stdin() io.WriteCloser { return h.stdin }
func (h *execNativeCampaignProcess) Stdout() io.ReadCloser { return h.stdout }
func (h *execNativeCampaignProcess) Stderr() io.ReadCloser { return h.stderr }
func (h *execNativeCampaignProcess) Wait() error           { return h.cmd.Wait() }
func (h *execNativeCampaignProcess) Kill() error {
	if h.cmd == nil || h.cmd.Process == nil {
		return nil
	}
	return h.cmd.Process.Kill()
}
func (h *execNativeCampaignProcess) Close() error {
	var err error
	h.closeMu.Do(func() {
		for _, closer := range []io.Closer{h.stdin, h.stdout, h.stderr} {
			if closer != nil {
				if cerr := closer.Close(); cerr != nil && err == nil {
					err = cerr
				}
			}
		}
	})
	return err
}

func defaultNativeCampaignProcessStarter(spec nativeCampaignProcessSpec) (nativeCampaignProcessHandle, error) {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return nil, errors.New("native campaign process argv is empty")
	}
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...)
	cmd.Dir = spec.Dir
	cmd.Env = spec.Env
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		return nil, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdinR, stdoutW, stderrW
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{stdinR, stdinW, stdoutR, stdoutW, stderrR, stderrW} {
			f.Close()
		}
		return nil, err
	}
	stdinR.Close()
	stdoutW.Close()
	stderrW.Close()
	return &execNativeCampaignProcess{cmd: cmd, stdin: stdinW, stdout: stdoutR, stderr: stderrR}, nil
}

// newNativeCampaignProcessFactory is the injectable factory boundary. It only
// constructs; no process is created until Start is called with a persisted,
// fenced start frame.
func newNativeCampaignProcessFactory(cfg nativeCampaignProcessConfig) nativeCampaignRunnerFactory {
	normalized := cfg.normalized()
	return func(_ context.Context, start nativeCampaignRunnerStart) (nativeCampaignRunner, error) {
		return newNativeCampaignProcessRunner(normalized, start), nil
	}
}

type nativeCampaignStartWire struct {
	ResourcePlan         *nativeCampaignResourcePlan `json:"resource_plan,omitempty"`
	Operation            string                      `json:"operation"`
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
}

type nativeCampaignControlWire struct {
	RequestID     string `json:"request_id"`
	Action        string `json:"action"`
	Reason        string `json:"reason,omitempty"`
	LeaseMS       int64  `json:"lease_ms,omitempty"`
	LeaseDeadline string `json:"lease_deadline,omitempty"`
}

type nativeCampaignCleanupProbeWire struct {
	ResourcePlan *nativeCampaignResourcePlan `json:"resource_plan,omitempty"`
	CreationSeal *nativeCampaignCreationSeal `json:"creation_seal,omitempty"`
	Operation    string                      `json:"operation"`
	RequestID    string                      `json:"request_id"`
	TaskID       int64                       `json:"task_id"`
	CampaignID   int64                       `json:"campaign_id"`
	AttemptID    int64                       `json:"attempt_id"`
	FencingToken int64                       `json:"fencing_token"`
}

type nativeCampaignWireFrame struct {
	RequestID    string          `json:"request_id"`
	TaskID       int64           `json:"task_id,omitempty"`
	CampaignID   int64           `json:"campaign_id,omitempty"`
	AttemptID    int64           `json:"attempt_id,omitempty"`
	FencingToken int64           `json:"fencing_token,omitempty"`
	EventSeq     int64           `json:"event_seq,omitempty"`
	Kind         string          `json:"kind"`
	Observation  json.RawMessage `json:"observation"`
}

type nativeCampaignControlAck struct {
	Action        string          `json:"action,omitempty"`
	Accepted      bool            `json:"accepted,omitempty"`
	LeaseDeadline string          `json:"lease_deadline,omitempty"`
	Status        json.RawMessage `json:"status,omitempty"`
	Detail        string          `json:"detail,omitempty"`
}

type nativeCampaignCheckpointEntry struct {
	SHA256     string `json:"sha256"`
	Length     int    `json:"length"`
	DataBase64 string `json:"data_base64"`
	SourceType string `json:"source_type,omitempty"`
	SourceRef  string `json:"source_ref,omitempty"`
	// StorageKey is optional on the wire. When present it must equal the key
	// derived from the trusted task id and hash; it is never trusted directly.
	StorageKey string `json:"storage_key,omitempty"`
}

// nativeCampaignCheckpointRecord retains only bounded metadata from a verified
// chunk entry. Validated bytes are retained only within the 1 MiB corpus bound
// for the persistence handoff; canonical JSON still contains metadata only.
type nativeCampaignCheckpointRecord struct {
	Data       []byte // internal validated bytes; never serialized into final JSON
	SHA256     string
	Length     int
	StorageKey string
	SourceType string
	SourceRef  string
}

func nativeCampaignCheckpointSourceTypeValid(value string) bool {
	switch value {
	case "seed", "queue", "crash", "import":
		return true
	default:
		return false
	}
}

func validateNativeCampaignSourceRef(value string) error {
	if value == "" || utf8.RuneCountInString(value) > 256 {
		return fmt.Errorf("%w: checkpoint source_ref length is invalid", errNativeCampaignProtocolViolation)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: checkpoint source_ref is not valid UTF-8", errNativeCampaignProtocolViolation)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: checkpoint source_ref has a control character", errNativeCampaignProtocolViolation)
		}
	}
	if strings.ContainsRune(value, '\\') || strings.HasPrefix(value, "/") {
		return fmt.Errorf("%w: checkpoint source_ref must be relative", errNativeCampaignProtocolViolation)
	}
	if len(value) >= 2 && isNativeCampaignASCIILetter(value[0]) && value[1] == ':' {
		return fmt.Errorf("%w: checkpoint source_ref must not be a drive path", errNativeCampaignProtocolViolation)
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("%w: checkpoint source_ref traversal is not allowed", errNativeCampaignProtocolViolation)
		}
	}
	return nil
}

func isNativeCampaignASCIILetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func nativeCampaignCheckpointStorageKey(taskID int64, sha256Value string) string {
	prefix := sha256Value
	if len(prefix) > 2 {
		prefix = prefix[:2]
	}
	return fmt.Sprintf("tasks/%d/reverse/campaigns/objects/sha256/%s/%s", taskID, prefix, sha256Value)
}

func appendNativeCampaignCanonicalString(dst []byte, value string) ([]byte, error) {
	raw, err := db.AppendNativeCampaignCanonicalString(dst, value)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNativeCampaignProtocolViolation, err)
	}
	return raw, nil
}

func sortNativeCampaignCheckpointRecords(records []nativeCampaignCheckpointRecord) {
	sort.Slice(records, func(i, j int) bool {
		left, right := records[i], records[j]
		if left.SourceType != right.SourceType {
			return left.SourceType < right.SourceType
		}
		if left.StorageKey != right.StorageKey {
			return left.StorageKey < right.StorageKey
		}
		if left.SHA256 != right.SHA256 {
			return left.SHA256 < right.SHA256
		}
		return left.Length < right.Length
	})
}

// nativeCampaignCanonicalManifest builds the exact taskbook section 3.3
// manifest from trusted identity plus receiver-validated unique records. The
// builder is byte-compatible with Python's canonical JSON encoder.
func nativeCampaignCanonicalManifest(taskID, campaignID, attemptID int64, records []nativeCampaignCheckpointRecord) ([]byte, error) {
	entries := make([]db.NativeCampaignEntryInput, len(records))
	for i, r := range records {
		entries[i] = db.NativeCampaignEntryInput{Length: int64(r.Length), SHA256: r.SHA256, SourceRef: r.SourceRef, SourceType: r.SourceType, StorageKey: r.StorageKey}
	}
	raw, err := db.CanonicalNativeCampaignManifest(campaignID, attemptID, entries)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errNativeCampaignProtocolViolation, err)
	}
	return raw, nil
}

type nativeCampaignCheckpointObservation struct {
	Event         string                          `json:"event"`
	CheckpointSeq int                             `json:"checkpoint_seq"`
	Entries       []nativeCampaignCheckpointEntry `json:"entries"`
	More          bool                            `json:"more"`
}

// checkNativeCampaignJSONNoDuplicateKeys walks the full JSON token stream. Go's
// encoding/json would silently keep the last duplicate, which is not acceptable
// for a control protocol.
func checkNativeCampaignJSONNoDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyTok.(string)
				if !ok {
					return fmt.Errorf("%w: object key is not a string", errNativeCampaignProtocolViolation)
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("%w: duplicate JSON key %q", errNativeCampaignProtocolViolation, key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		default:
			return fmt.Errorf("%w: unexpected JSON delimiter", errNativeCampaignProtocolViolation)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON data", errNativeCampaignProtocolViolation)
	}
	return nil
}

// nativeCampaignHex4 decodes exactly four hexadecimal digits.
func nativeCampaignHex4(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, ch := range raw {
		value <<= 4
		switch {
		case ch >= '0' && ch <= '9':
			value |= uint16(ch - '0')
		case ch >= 'a' && ch <= 'f':
			value |= uint16(ch-'a') + 10
		case ch >= 'A' && ch <= 'F':
			value |= uint16(ch-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// checkNativeCampaignJSONUnicode rejects invalid UTF-8 and lone UTF-16
// surrogate escapes. Go's encoding/json silently replaces both with U+FFFD,
// which would otherwise let a non-canonical source_ref through.
func checkNativeCampaignJSONUnicode(raw []byte) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("%w: JSON payload is not valid UTF-8", errNativeCampaignProtocolViolation)
	}
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			return fmt.Errorf("%w: truncated JSON escape", errNativeCampaignProtocolViolation)
		}
		switch raw[i+1] {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			i += 2
		case 'u':
			if i+6 > len(raw) {
				return fmt.Errorf("%w: truncated JSON unicode escape", errNativeCampaignProtocolViolation)
			}
			code, ok := nativeCampaignHex4(raw[i+2 : i+6])
			if !ok {
				return fmt.Errorf("%w: invalid JSON unicode escape", errNativeCampaignProtocolViolation)
			}
			switch {
			case code >= 0xd800 && code <= 0xdbff:
				if i+12 > len(raw) || raw[i+6] != '\\' || raw[i+7] != 'u' {
					return fmt.Errorf("%w: lone high surrogate", errNativeCampaignProtocolViolation)
				}
				low, ok := nativeCampaignHex4(raw[i+8 : i+12])
				if !ok || low < 0xdc00 || low > 0xdfff {
					return fmt.Errorf("%w: lone high surrogate", errNativeCampaignProtocolViolation)
				}
				i += 12
			case code >= 0xdc00 && code <= 0xdfff:
				return fmt.Errorf("%w: lone low surrogate", errNativeCampaignProtocolViolation)
			default:
				i += 6
			}
		default:
			return fmt.Errorf("%w: invalid JSON escape", errNativeCampaignProtocolViolation)
		}
	}
	return nil
}

func strictNativeCampaignUnmarshal(raw []byte, dst any) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty JSON payload", errNativeCampaignProtocolViolation)
	}
	if err := checkNativeCampaignJSONUnicode(raw); err != nil {
		return err
	}
	if err := checkNativeCampaignJSONNoDuplicateKeys(raw); err != nil {
		if errors.Is(err, errNativeCampaignProtocolViolation) {
			return err
		}
		// Tokenization can fail before duplicate-key validation. Preserve the
		// JSON cause while giving all malformed wire input the protocol type.
		return fmt.Errorf("%w: invalid JSON payload: %w", errNativeCampaignProtocolViolation, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("%w: invalid JSON payload: %v", errNativeCampaignProtocolViolation, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing JSON data", errNativeCampaignProtocolViolation)
	}
	return nil
}

func decodeNativeCampaignWireFrame(line []byte) (*nativeCampaignWireFrame, error) {
	var frame nativeCampaignWireFrame
	if err := strictNativeCampaignUnmarshal(line, &frame); err != nil {
		return nil, err
	}
	if strings.TrimSpace(frame.RequestID) == "" || len(frame.RequestID) > 128 {
		return nil, fmt.Errorf("%w: invalid frame request_id", errNativeCampaignProtocolViolation)
	}
	switch frame.Kind {
	case "event", "phase", "checkpoint_chunk", "result", "final":
	default:
		return nil, fmt.Errorf("%w: unknown frame kind %q", errNativeCampaignProtocolViolation, frame.Kind)
	}
	trimmed := bytes.TrimSpace(frame.Observation)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil, fmt.Errorf("%w: frame observation must be a JSON object", errNativeCampaignProtocolViolation)
	}
	if frame.Kind == "final" || frame.Kind == "result" {
		if frame.TaskID <= 0 || frame.CampaignID <= 0 || frame.AttemptID <= 0 || frame.FencingToken <= 0 {
			return nil, fmt.Errorf("%w: %s frame identity is incomplete", errNativeCampaignProtocolViolation, frame.Kind)
		}
	}
	return &frame, nil
}

func decodeNativeCampaignFinalFrame(frame *nativeCampaignWireFrame, expect nativeCampaignFrameExpectation) (nativeCampaignRunnerFinal, error) {
	var final nativeCampaignRunnerFinal
	if frame.RequestID != expect.RequestID || frame.TaskID != expect.TaskID ||
		frame.CampaignID != expect.CampaignID || frame.AttemptID != expect.AttemptID ||
		frame.FencingToken != expect.FencingToken {
		return final, fmt.Errorf("%w: final envelope identity/fence does not match", errNativeCampaignProtocolViolation)
	}
	if err := strictNativeCampaignUnmarshal(frame.Observation, &final); err != nil {
		return final, err
	}
	// If the observation repeats identity fields they must agree with the
	// envelope; missing fields are bound from the already-validated envelope.
	if final.RequestID != "" && final.RequestID != frame.RequestID {
		return final, fmt.Errorf("%w: final observation request_id mismatch", errNativeCampaignProtocolViolation)
	}
	if final.TaskID != 0 && final.TaskID != frame.TaskID {
		return final, fmt.Errorf("%w: final observation task_id mismatch", errNativeCampaignProtocolViolation)
	}
	if final.CampaignID != 0 && final.CampaignID != frame.CampaignID {
		return final, fmt.Errorf("%w: final observation campaign_id mismatch", errNativeCampaignProtocolViolation)
	}
	if final.AttemptID != 0 && final.AttemptID != frame.AttemptID {
		return final, fmt.Errorf("%w: final observation attempt_id mismatch", errNativeCampaignProtocolViolation)
	}
	if final.FencingToken != 0 && final.FencingToken != frame.FencingToken {
		return final, fmt.Errorf("%w: final observation fencing_token mismatch", errNativeCampaignProtocolViolation)
	}
	final.RequestID, final.TaskID = frame.RequestID, frame.TaskID
	final.CampaignID, final.AttemptID = frame.CampaignID, frame.AttemptID
	final.FencingToken = frame.FencingToken
	if err := final.Validate(expect); err != nil {
		return final, err
	}
	return final, nil
}

func decodeNativeCampaignControlAck(frame *nativeCampaignWireFrame, expect nativeCampaignFrameExpectation) (nativeCampaignControlAck, error) {
	var ack nativeCampaignControlAck
	if frame.TaskID != expect.TaskID ||
		frame.CampaignID != expect.CampaignID || frame.AttemptID != expect.AttemptID ||
		frame.FencingToken != expect.FencingToken {
		return ack, fmt.Errorf("%w: control ACK identity/fence does not match", errNativeCampaignProtocolViolation)
	}
	if err := strictNativeCampaignUnmarshal(frame.Observation, &ack); err != nil {
		return ack, err
	}
	if len(ack.Status) > 0 {
		var v any
		if err := strictNativeCampaignUnmarshal(ack.Status, &v); err != nil {
			return ack, err
		}
	}
	if len(ack.Detail) > 512 {
		return ack, fmt.Errorf("%w: control ACK detail is too long", errNativeCampaignProtocolViolation)
	}
	if ack.LeaseDeadline != "" {
		if _, err := time.Parse(time.RFC3339Nano, ack.LeaseDeadline); err != nil {
			return ack, fmt.Errorf("%w: invalid lease_deadline", errNativeCampaignProtocolViolation)
		}
	}
	return ack, nil
}

func validateNativeCampaignProcessStart(start nativeCampaignRunnerStart) error {
	if err := start.Validate(); err != nil {
		return err
	}
	if len(start.Seeds) < 1 || len(start.Seeds) > NativeCampaignMaxSeeds {
		return fmt.Errorf("%w: real process transport requires 1..32 seeds", errNativeCampaignProtocolViolation)
	}
	execution, err := time.Parse(time.RFC3339Nano, start.ExecutionDeadline)
	if err != nil {
		return fmt.Errorf("%w: invalid execution_deadline", errNativeCampaignProtocolViolation)
	}
	envelope, err := time.Parse(time.RFC3339Nano, start.EnvelopeDeadline)
	if err != nil {
		return fmt.Errorf("%w: invalid envelope_deadline", errNativeCampaignProtocolViolation)
	}
	if execution.After(envelope) {
		return fmt.Errorf("%w: execution deadline is after the envelope deadline", errNativeCampaignProtocolViolation)
	}
	if start.CleanupHardTimeoutMS < 1000 || start.CleanupHardTimeoutMS > 60000 {
		return fmt.Errorf("%w: invalid cleanup hard timeout", errNativeCampaignProtocolViolation)
	}
	return nil
}

type nativeCampaignProcessPending struct {
	fingerprint   string
	action        string
	leaseDeadline time.Time
	// ch is retained for compatibility with the independent read-only review
	// fixture; production completion uses the broadcast done/result pair.
	ch     chan error
	done   chan struct{}
	result error
}

type nativeCampaignProcessCached struct {
	fingerprint string
	err         error
}

type nativeCampaignProcessRunner struct {
	cfg   nativeCampaignProcessConfig
	start nativeCampaignRunnerStart

	executionDeadline time.Time
	envelopeDeadline  time.Time
	deadline          time.Time
	startedAt         time.Time

	events     chan nativeCampaignRunnerEvent
	eventsOnce sync.Once

	done        chan struct{}
	processDone chan struct{}
	readerDone  chan struct{}
	stderrDone  chan struct{}
	stop        chan struct{}
	stopOnce    sync.Once

	stdinCh     chan []byte
	stdinStop   chan struct{}
	stdinOnce   sync.Once
	writerDone  chan struct{}
	stdinClosed sync.Once

	leaseWake chan struct{}

	mu             sync.Mutex
	handle         nativeCampaignProcessHandle
	started        bool
	final          nativeCampaignRunnerFinal
	finalSeen      bool
	readerErr      error
	processErr     error
	deadlineHit    string
	leaseExpired   bool
	leaseDeadline  time.Time
	killRequested  bool
	stopping       bool
	stderrTail     []byte
	probeStderr    []byte
	pending        map[string]*nativeCampaignProcessPending
	cache          map[string]nativeCampaignProcessCached
	abandoned      map[string]struct{}
	abandonedOrder []string
	chunkSeq       int
	chunkEntries   int
	chunkBytes     int64
	chunkSeen      bool
	chunkFinished  bool
	chunkRecords   []nativeCampaignCheckpointRecord
	chunkUnique    map[string]struct{}
}

func newNativeCampaignProcessRunner(cfg nativeCampaignProcessConfig, start nativeCampaignRunnerStart) *nativeCampaignProcessRunner {
	cfg = cfg.normalized()
	return &nativeCampaignProcessRunner{
		cfg: cfg, start: start,
		events:      make(chan nativeCampaignRunnerEvent, nativeCampaignEventQueue),
		done:        make(chan struct{}),
		processDone: make(chan struct{}),
		readerDone:  make(chan struct{}),
		stderrDone:  make(chan struct{}),
		stop:        make(chan struct{}),
		stdinCh:     make(chan []byte, nativeCampaignProcessQueue),
		stdinStop:   make(chan struct{}),
		writerDone:  make(chan struct{}),
		leaseWake:   make(chan struct{}, 1),
		pending:     map[string]*nativeCampaignProcessPending{},
		cache:       map[string]nativeCampaignProcessCached{},
		abandoned:   map[string]struct{}{},
		chunkUnique: map[string]struct{}{},
	}
}

func (r *nativeCampaignProcessRunner) expectation() nativeCampaignFrameExpectation {
	return nativeCampaignFrameExpectation{
		RequestID: r.start.RequestID, TaskID: r.start.TaskID,
		CampaignID: r.start.CampaignID, AttemptID: r.start.AttemptID,
		FencingToken: r.start.FencingToken,
	}
}

func (r *nativeCampaignProcessRunner) Events() <-chan nativeCampaignRunnerEvent { return r.events }

// Diagnostics returns a bounded tail of the runner's stderr. The wire protocol hides
// transport/runner detail from the ledger on purpose, so an operator debugging a
// stalled attempt needs the child's own message somewhere; this never leaves the log.
func (r *nativeCampaignProcessRunner) Diagnostics() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	parts := make([]string, 0, 2)
	if len(r.probeStderr) > 0 {
		parts = append(parts, "probe: "+string(r.probeStderr))
	}
	if len(r.stderrTail) > 0 {
		parts = append(parts, "stderr: "+string(r.stderrTail))
	}
	out := strings.Join(parts, " | ")
	if len(out) > 2048 {
		out = out[len(out)-2048:]
	}
	return out
}
func (r *nativeCampaignProcessRunner) closeEvents() {
	r.eventsOnce.Do(func() { close(r.events) })
}

func (r *nativeCampaignProcessRunner) Start(ctx context.Context, start nativeCampaignRunnerStart) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateNativeCampaignProcessStart(start); err != nil {
		return err
	}
	// A resumed attempt carries the checkpoint as seeds; a compact summary makes a
	// rejected resume debuggable without dumping corpus bytes.
	if os.Getenv("ARTEX_CAMPAIGN_TRACE") == "1" {
		kinds := map[string]int{}
		bytes := 0
		for _, seed := range start.Seeds {
			bytes += len(seed.DataBase64)
			kinds[seed.SourceType]++
		}
		log.Printf("[native campaign trace] start campaign=%d attempt=%d no=%d seeds=%d bytes=%d kinds=%v owned=%d argv=%d",
			start.CampaignID, start.AttemptID, start.AttemptNo, len(start.Seeds), bytes, kinds, len(start.OwnedResources), len(start.Argv))
	}
	execution, err := time.Parse(time.RFC3339Nano, start.ExecutionDeadline)
	if err != nil {
		return fmt.Errorf("%w: invalid execution_deadline", errNativeCampaignProtocolViolation)
	}
	envelope, err := time.Parse(time.RFC3339Nano, start.EnvelopeDeadline)
	if err != nil {
		return fmt.Errorf("%w: invalid envelope_deadline", errNativeCampaignProtocolViolation)
	}
	now := time.Now()
	deadline := execution
	if envelope.Before(deadline) {
		deadline = envelope
	}
	if budget := now.Add(time.Duration(start.AttemptBudgetMS) * time.Millisecond); budget.Before(deadline) {
		deadline = budget
	}
	if !now.Before(deadline) {
		return fmt.Errorf("%w: absolute deadline passed before start", errNativeCampaignProcessDeadline)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	initialLease, _ := time.Parse(time.RFC3339Nano, start.LeaseDeadline)
	if !initialLease.After(now) {
		return errNativeCampaignProcessLeaseExpired
	}
	resourcePlan, err := nativeCampaignPlanFromResources(start.OwnedResources)
	if err != nil {
		return fmt.Errorf("%w: invalid resource plan", errNativeCampaignProtocolViolation)
	}
	wire, err := json.Marshal(nativeCampaignStartWire{
		ResourcePlan: resourcePlan,
		Operation:    "campaign", TaskID: start.TaskID, RequestID: start.RequestID,
		CampaignID: start.CampaignID, AttemptID: start.AttemptID, AttemptNo: start.AttemptNo,
		FencingToken: start.FencingToken, LeaseOwner: start.LeaseOwner,
		LeaseInstance: start.LeaseInstance, LeaseMS: start.LeaseMS, LeaseDeadline: start.LeaseDeadline,
		ArtifactPath: start.ArtifactPath, SHA256: start.SHA256, Argv: start.Argv,
		InputMode: start.InputMode, Seeds: start.Seeds, MaxExecutions: start.MaxExecutions,
		MaxCrashes: start.MaxCrashes, AttemptBudgetMS: start.AttemptBudgetMS,
		ExecutionWindowMS: start.ExecutionWindowMS, ExecutionDeadline: start.ExecutionDeadline,
		EnvelopeDeadline: start.EnvelopeDeadline, CleanupReserveMS: start.CleanupReserveMS,
		CleanupHardTimeoutMS: start.CleanupHardTimeoutMS, Profile: start.Profile,
	})
	if err != nil {
		return fmt.Errorf("%w: cannot encode start frame", errNativeCampaignProtocolViolation)
	}
	wire = append(wire, '\n')
	if len(wire) > NativeCampaignMaxFrameBytes {
		return fmt.Errorf("%w: start frame exceeds 1 MiB", errNativeCampaignProtocolViolation)
	}

	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return fmt.Errorf("%w: process transport was already started", errNativeCampaignProtocolViolation)
	}
	r.started = true
	r.startedAt = now
	r.executionDeadline = execution
	r.envelopeDeadline = envelope
	r.deadline = deadline
	r.leaseDeadline, _ = time.Parse(time.RFC3339Nano, start.LeaseDeadline)
	r.mu.Unlock()

	handle, err := r.cfg.Starter(nativeCampaignProcessSpec{
		Argv: append([]string(nil), r.cfg.Command...), Dir: r.cfg.Dir, Env: append([]string(nil), r.cfg.Env...),
	})
	if err != nil {
		r.mu.Lock()
		r.processErr = err
		r.mu.Unlock()
		close(r.processDone)
		close(r.readerDone)
		close(r.stderrDone)
		close(r.writerDone)
		r.closeEvents()
		close(r.done)
		return fmt.Errorf("%w: cannot start process: %v", errNativeCampaignProtocolViolation, err)
	}
	r.mu.Lock()
	r.handle = handle
	r.mu.Unlock()

	go r.finishWatcher()
	go r.stdinLoop()
	go r.stderrLoop()
	go r.stdoutLoop()
	go r.processLoop()
	go r.deadlineLoop()

	if err := r.enqueue(ctx, wire); err != nil {
		r.shutdown(true)
		timer := time.NewTimer(nativeCampaignControlWriteTimeout)
		select {
		case <-r.done:
		case <-timer.C:
		}
		timer.Stop()
		return fmt.Errorf("%w: cannot deliver start frame: %v", errNativeCampaignProtocolViolation, err)
	}
	return nil
}

// finishWatcher is the single aggregate completion point. done (and therefore
// Wait/Events success) is withheld until process reap, stdout reader, stderr
// reader and stdin writer have all terminated. No final frame can fake a
// successful Wait while an owned goroutine or process is still alive.
func (r *nativeCampaignProcessRunner) finishWatcher() {
	<-r.processDone
	// The process is gone: no further stdin can be consumed. This also releases
	// a writer blocked in Write.
	r.closeStdin()
	<-r.writerDone
	<-r.stderrDone
	<-r.readerDone
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle != nil {
		_ = handle.Close()
	}
	r.closeEvents()
	close(r.done)
}

func (r *nativeCampaignProcessRunner) stdinLoop() {
	defer close(r.writerDone)
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle == nil {
		return
	}
	stdin := handle.Stdin()
	if stdin == nil {
		return
	}
	for {
		select {
		case <-r.stdinStop:
			return
		case <-r.stop:
			return
		case <-r.processDone:
			return
		case data := <-r.stdinCh:
			for len(data) > 0 {
				n, err := stdin.Write(data)
				if n > 0 {
					data = data[n:]
				}
				if err != nil {
					return
				}
				if n == 0 {
					return
				}
			}
		}
	}
}

func (r *nativeCampaignProcessRunner) stderrLoop() {
	defer close(r.stderrDone)
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle == nil {
		return
	}
	stderr := handle.Stderr()
	if stderr == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := stderr.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.stderrTail = append(r.stderrTail, buf[:n]...)
			if len(r.stderrTail) > nativeCampaignStderrMax {
				r.stderrTail = r.stderrTail[len(r.stderrTail)-nativeCampaignStderrMax:]
			}
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *nativeCampaignProcessRunner) processLoop() {
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle == nil {
		close(r.processDone)
		return
	}
	err := handle.Wait()
	r.mu.Lock()
	r.processErr = err
	r.mu.Unlock()
	close(r.processDone)
}

func (r *nativeCampaignProcessRunner) stdoutLoop() {
	defer close(r.readerDone)
	r.mu.Lock()
	handle := r.handle
	r.mu.Unlock()
	if handle == nil {
		return
	}
	br := bufio.NewReaderSize(handle.Stdout(), 64<<10)
	var total int64
	for {
		line, terminated, err := readNativeCampaignProcessLine(br, NativeCampaignMaxFrameBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			r.failReader(err)
			return
		}
		if !terminated {
			r.failReader(fmt.Errorf("%w: truncated protocol frame", errNativeCampaignProtocolViolation))
			return
		}
		total += int64(len(line)) + 1
		if total > NativeCampaignMaxEvidenceTotal {
			r.failReader(errNativeCampaignEvidenceLimit)
			return
		}
		frame, err := decodeNativeCampaignWireFrame(line)
		if err != nil {
			r.failReader(err)
			return
		}
		if err := r.dispatchFrame(frame); err != nil {
			r.failReader(err)
			return
		}
	}
	if err := r.finishStream(); err != nil {
		r.failReader(err)
	}
}

func readNativeCampaignProcessLine(br *bufio.Reader, max int) ([]byte, bool, error) {
	var line []byte
	for {
		part, err := br.ReadSlice('\n')
		if len(line)+len(part) > max {
			return nil, false, fmt.Errorf("%w: frame exceeds 1 MiB", errNativeCampaignProtocolViolation)
		}
		line = append(line, part...)
		switch {
		case err == nil:
			line = bytes.TrimSuffix(line, []byte("\n"))
			line = bytes.TrimSuffix(line, []byte("\r"))
			return line, true, nil
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF:
			if len(line) == 0 {
				return nil, false, io.EOF
			}
			return nil, false, fmt.Errorf("%w: truncated protocol frame", errNativeCampaignProtocolViolation)
		default:
			return nil, false, fmt.Errorf("%w: read frame: %v", errNativeCampaignProtocolViolation, err)
		}
	}
}

func (r *nativeCampaignProcessRunner) dispatchFrame(frame *nativeCampaignWireFrame) error {
	expect := r.expectation()
	if frame.Kind != "result" && frame.RequestID != expect.RequestID {
		return fmt.Errorf("%w: frame request_id does not match", errNativeCampaignProtocolViolation)
	}
	if frame.TaskID != 0 && frame.TaskID != expect.TaskID {
		return fmt.Errorf("%w: frame task_id does not match", errNativeCampaignProtocolViolation)
	}
	if frame.CampaignID != 0 && frame.CampaignID != expect.CampaignID {
		return fmt.Errorf("%w: frame campaign_id does not match", errNativeCampaignProtocolViolation)
	}
	switch frame.Kind {
	case "final":
		if r.finalSeen {
			return fmt.Errorf("%w: duplicate final frame", errNativeCampaignProtocolViolation)
		}
		final, err := decodeNativeCampaignFinalFrame(frame, expect)
		if err != nil {
			return err
		}
		r.mu.Lock()
		r.final, r.finalSeen = final, true
		r.mu.Unlock()
		return nil
	case "result":
		ack, err := decodeNativeCampaignControlAck(frame, expect)
		if err != nil {
			return err
		}
		return r.deliverControlAck(frame.RequestID, ack)
	case "event", "phase", "checkpoint_chunk":
		event := nativeCampaignRunnerEvent{
			RequestID: frame.RequestID, AttemptID: frame.AttemptID,
			FencingToken: frame.FencingToken, Kind: frame.Kind, Observation: frame.Observation,
		}
		if err := event.Validate(expect); err != nil {
			return err
		}
		if frame.Kind == "checkpoint_chunk" || nativeCampaignObservationEvent(frame.Observation) == "checkpoint_chunk" {
			if err := r.observeCheckpointChunk(frame.Observation); err != nil {
				return err
			}
		}
		select {
		case r.events <- event:
			return nil
		case <-r.stop:
			return errNativeCampaignProcessStopped
		}
	default:
		return fmt.Errorf("%w: unknown frame kind", errNativeCampaignProtocolViolation)
	}
}

func nativeCampaignObservationEvent(raw json.RawMessage) string {
	var probe struct {
		Event string `json:"event"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&probe); err != nil {
		return ""
	}
	return probe.Event
}

func (r *nativeCampaignProcessRunner) observeCheckpointChunk(raw json.RawMessage) error {
	var chunk nativeCampaignCheckpointObservation
	if err := strictNativeCampaignUnmarshal(raw, &chunk); err != nil {
		return err
	}
	if chunk.Event != "checkpoint_chunk" {
		return fmt.Errorf("%w: checkpoint chunk has the wrong event", errNativeCampaignProtocolViolation)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.chunkFinished {
		return fmt.Errorf("%w: checkpoint chunk after final chunk", errNativeCampaignProtocolViolation)
	}
	if chunk.CheckpointSeq != r.chunkSeq {
		return fmt.Errorf("%w: checkpoint chunk sequence %d, want %d", errNativeCampaignProtocolViolation, chunk.CheckpointSeq, r.chunkSeq)
	}
	if len(chunk.Entries) < 1 || len(chunk.Entries) > nativeCampaignCheckpointChunkLimit {
		return fmt.Errorf("%w: invalid checkpoint chunk entry count", errNativeCampaignProtocolViolation)
	}
	for _, entry := range chunk.Entries {
		data, err := base64.StdEncoding.Strict().DecodeString(entry.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(data) != entry.DataBase64 {
			return fmt.Errorf("%w: checkpoint entry is not canonical base64", errNativeCampaignProtocolViolation)
		}
		if len(data) < 1 || len(data) > NativeCampaignMaxObjectBytes || entry.Length != len(data) {
			return fmt.Errorf("%w: checkpoint entry size or length is invalid", errNativeCampaignProtocolViolation)
		}
		sum := sha256.Sum256(data)
		sha256Value := hex.EncodeToString(sum[:])
		if sha256Value != entry.SHA256 {
			return fmt.Errorf("%w: checkpoint entry hash mismatch", errNativeCampaignProtocolViolation)
		}
		if !nativeCampaignCheckpointSourceTypeValid(entry.SourceType) {
			return fmt.Errorf("%w: checkpoint entry source_type is not seed/queue/crash/import", errNativeCampaignProtocolViolation)
		}
		if err := validateNativeCampaignSourceRef(entry.SourceRef); err != nil {
			return err
		}
		storageKey := nativeCampaignCheckpointStorageKey(r.start.TaskID, sha256Value)
		if entry.StorageKey != "" && entry.StorageKey != storageKey {
			return fmt.Errorf("%w: checkpoint storage_key does not match the trusted task/hash", errNativeCampaignProtocolViolation)
		}
		uniqueKey := sha256Value + "\x00" + strconv.Itoa(entry.Length)
		if _, duplicate := r.chunkUnique[uniqueKey]; duplicate {
			return fmt.Errorf("%w: duplicate checkpoint (sha256,length) across chunks", errNativeCampaignProtocolViolation)
		}
		if r.chunkEntries >= NativeCampaignMaxCheckpointEntries ||
			r.chunkBytes+int64(len(data)) > 1<<20 {
			return fmt.Errorf("%w: checkpoint exceeds the bounded summary", errNativeCampaignProtocolViolation)
		}
		r.chunkUnique[uniqueKey] = struct{}{}
		r.chunkRecords = append(r.chunkRecords, nativeCampaignCheckpointRecord{
			Data: data, SHA256: sha256Value, Length: entry.Length, StorageKey: storageKey,
			SourceType: entry.SourceType, SourceRef: entry.SourceRef,
		})
		r.chunkEntries++
		r.chunkBytes += int64(len(data))
	}
	r.chunkSeen = true
	r.chunkSeq++
	if !chunk.More {
		r.chunkFinished = true
	}
	return nil
}

func (r *nativeCampaignProcessRunner) finishStream() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.finalSeen {
		return errNativeCampaignEOFWithoutFinal
	}
	if final := r.final.Checkpoint; final != nil {
		if !r.chunkSeen || !r.chunkFinished {
			return fmt.Errorf("%w: checkpoint summary without a complete chunk stream", errNativeCampaignProtocolViolation)
		}
		if r.chunkEntries != len(r.chunkRecords) {
			return fmt.Errorf("%w: checkpoint accounting is inconsistent", errNativeCampaignProtocolViolation)
		}
		manifest, err := nativeCampaignCanonicalManifest(
			r.start.TaskID, r.start.CampaignID, r.start.AttemptID, r.chunkRecords)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(manifest)
		if r.chunkEntries != final.EntryCount || r.chunkBytes != final.TotalBytes {
			return fmt.Errorf("%w: checkpoint summary does not match unique chunks", errNativeCampaignProtocolViolation)
		}
		if hex.EncodeToString(digest[:]) != final.ManifestSHA256 {
			return fmt.Errorf("%w: checkpoint canonical manifest hash does not match chunks", errNativeCampaignProtocolViolation)
		}
	} else if r.chunkSeen {
		return fmt.Errorf("%w: checkpoint chunks without a final summary", errNativeCampaignProtocolViolation)
	}
	return nil
}

func (r *nativeCampaignProcessRunner) failReader(err error) {
	r.mu.Lock()
	if r.readerErr == nil {
		r.readerErr = err
	}
	r.mu.Unlock()
	// EOF alone is derived evidence, not a malformed frame. Do not kill the
	// process here and then mistake our own kill for an abnormal exit. Existing
	// lease/execution/Wait deadlines retain ownership and bound a silent peer.
	if err != errNativeCampaignEOFWithoutFinal {
		r.killNow()
	}
}

// resolvePendingLocked publishes one immutable result to every waiter sharing
// the request_id, then caches it for idempotent replay. It must be called with
// r.mu held.
func (r *nativeCampaignProcessRunner) resolvePendingLocked(requestID string, pending *nativeCampaignProcessPending, result error) {
	if pending.done == nil {
		pending.done = make(chan struct{})
	}
	pending.result = result
	r.cacheControlLocked(requestID, pending.fingerprint, result)
	delete(r.pending, requestID)
	close(pending.done)
}

func (r *nativeCampaignProcessRunner) failPendingLocked(err error) {
	for requestID, pending := range r.pending {
		// A late ACK after the shared deadline is a dropped replay, not a new
		// control: keep the bounded abandoned ledger so it cannot poison the
		// stream or be mistaken for a fresh request.
		r.abandonLocked(requestID)
		r.resolvePendingLocked(requestID, pending, err)
	}
}

func (r *nativeCampaignProcessRunner) deliverControlAck(requestID string, ack nativeCampaignControlAck) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	pending, ok := r.pending[requestID]
	if !ok {
		if _, abandoned := r.abandoned[requestID]; abandoned {
			delete(r.abandoned, requestID)
			return nil
		}
		return fmt.Errorf("%w: result for unknown control request_id %q", errNativeCampaignProtocolViolation, requestID)
	}
	// Validate the complete ACK before touching any lease state. A malformed or
	// expired heartbeat ACK must never partially renew, revive or extend a lease.
	if ack.Action != pending.action {
		r.resolvePendingLocked(requestID, pending,
			fmt.Errorf("%w: control ACK action mismatch", errNativeCampaignProtocolViolation))
		return nil
	}
	if !ack.Accepted {
		r.resolvePendingLocked(requestID, pending,
			fmt.Errorf("%w: control was rejected: %s", errNativeCampaignProtocolViolation, ack.Detail))
		return nil
	}
	if pending.action == "heartbeat" {
		now := time.Now()
		if ack.LeaseDeadline == "" {
			r.resolvePendingLocked(requestID, pending,
				fmt.Errorf("%w: accepted heartbeat ACK has no lease_deadline", errNativeCampaignProtocolViolation))
			return nil
		}
		reported, err := time.Parse(time.RFC3339Nano, ack.LeaseDeadline)
		if err != nil || !reported.After(now) || reported.After(r.deadline) || pending.leaseDeadline.IsZero() || reported.After(pending.leaseDeadline) {
			r.resolvePendingLocked(requestID, pending,
				fmt.Errorf("%w: heartbeat lease_deadline is not a plausible deadline", errNativeCampaignProtocolViolation))
			return nil
		}
		// The exact authority sent in the request is fixed across queue/ACK
		// delays and retries. Never derive a new cutoff from receipt time.
		proposed := reported
		if r.leaseExpired || !now.Before(r.leaseDeadline) {
			r.leaseExpired = true
			r.resolvePendingLocked(requestID, pending, errNativeCampaignProcessLeaseExpired)
			return nil
		}
		if !now.Before(r.deadline) {
			r.resolvePendingLocked(requestID, pending, errNativeCampaignProcessDeadline)
			return nil
		}
		r.leaseDeadline = proposed
		r.leaseExpired = false
		select {
		case r.leaseWake <- struct{}{}:
		default:
		}
	}
	r.resolvePendingLocked(requestID, pending, nil)
	return nil
}

func (r *nativeCampaignProcessRunner) cacheControlLocked(requestID, fingerprint string, err error) {
	// The ledger is never silently evicted: an old request_id must always keep
	// its immutable result so a replay cannot re-execute a heartbeat or control
	// side effect. Capacity is enforced before a new request is sent.
	r.cache[requestID] = nativeCampaignProcessCached{fingerprint: fingerprint, err: err}
}

func (r *nativeCampaignProcessRunner) abandonLocked(requestID string) {
	if _, exists := r.abandoned[requestID]; exists {
		return
	}
	r.abandoned[requestID] = struct{}{}
	r.abandonedOrder = append(r.abandonedOrder, requestID)
	for len(r.abandonedOrder) > nativeCampaignControlAbandonedMax {
		oldest := r.abandonedOrder[0]
		r.abandonedOrder = r.abandonedOrder[1:]
		delete(r.abandoned, oldest)
	}
}

func (r *nativeCampaignProcessRunner) enqueue(ctx context.Context, data []byte) error {
	select {
	case <-r.stop:
		return errNativeCampaignProcessStopped
	default:
	}
	select {
	case r.stdinCh <- data:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stop:
		return errNativeCampaignProcessStopped
	}
}

func (r *nativeCampaignProcessRunner) waitPending(ctx context.Context, requestID string, pending *nativeCampaignProcessPending, done <-chan struct{}) error {
	r.mu.Lock()
	deadline := r.deadline
	r.mu.Unlock()
	var timer *time.Timer
	var timerC <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timerC = timer.C
	}
	select {
	case <-done:
		// resolvePendingLocked writes result before closing done, so this read is
		// the shared immutable completion result for every waiter.
		return pending.result
	case <-timerC:
		r.mu.Lock()
		if current, ok := r.pending[requestID]; ok && current == pending {
			r.abandonLocked(requestID)
			r.resolvePendingLocked(requestID, pending, errNativeCampaignProcessDeadline)
		}
		r.mu.Unlock()
		return errNativeCampaignProcessDeadline
	case <-ctx.Done():
		// A single caller's cancellation must not discard the shared pending
		// entry: other callers may still be waiting for the same ACK.
		return ctx.Err()
	case <-r.done:
		return errNativeCampaignProcessStopped
	}
}

func (r *nativeCampaignProcessRunner) Control(ctx context.Context, control nativeCampaignRunnerControl) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := control.Validate(); err != nil {
		return err
	}
	now := time.Now()
	fingerprint := fmt.Sprintf("%s\x00%s\x00%d", control.Action, control.Reason, control.LeaseMS)
	if control.Action == "heartbeat" {
		fingerprint += "\x00" + control.LeaseDeadline
	}
	r.mu.Lock()
	if !r.started || r.handle == nil {
		r.mu.Unlock()
		return fmt.Errorf("%w: process transport is not started", errNativeCampaignProtocolViolation)
	}
	if !now.Before(r.deadline) {
		r.mu.Unlock()
		r.initiateCancel("execution_deadline")
		return errNativeCampaignProcessDeadline
	}
	if control.Action == "heartbeat" && (r.leaseExpired || !now.Before(r.leaseDeadline)) {
		r.leaseExpired = true
		r.mu.Unlock()
		r.initiateCancel("lease_expired")
		return errNativeCampaignProcessLeaseExpired
	}
	if cached, ok := r.cache[control.RequestID]; ok {
		r.mu.Unlock()
		if cached.fingerprint != fingerprint {
			return fmt.Errorf("%w: control request_id reused with different content", errNativeCampaignProtocolViolation)
		}
		return cached.err
	}
	if pending, ok := r.pending[control.RequestID]; ok {
		if pending.fingerprint != fingerprint {
			r.mu.Unlock()
			return fmt.Errorf("%w: control request_id reused with different content", errNativeCampaignProtocolViolation)
		}
		if pending.done == nil {
			pending.done = make(chan struct{})
		}
		done := pending.done
		r.mu.Unlock()
		return r.waitPending(ctx, control.RequestID, pending, done)
	}
	if len(r.pending) >= nativeCampaignControlPendingMax {
		r.mu.Unlock()
		return fmt.Errorf("%w: too many pending controls", errNativeCampaignProtocolViolation)
	}
	if len(r.cache)+len(r.pending) >= nativeCampaignControlLedgerMax {
		r.mu.Unlock()
		return fmt.Errorf("%w: control ledger capacity exhausted", errNativeCampaignProtocolViolation)
	}
	requestedLease, _ := time.Parse(time.RFC3339Nano, control.LeaseDeadline)
	if control.Action == "heartbeat" && (!requestedLease.After(now) || requestedLease.After(r.deadline)) {
		r.mu.Unlock()
		return fmt.Errorf("%w: heartbeat absolute lease outside execution window", errNativeCampaignProtocolViolation)
	}
	pending := &nativeCampaignProcessPending{
		fingerprint: fingerprint, action: control.Action,
		leaseDeadline: requestedLease, ch: make(chan error, 1), done: make(chan struct{}),
	}
	r.pending[control.RequestID] = pending
	r.mu.Unlock()

	wire, err := json.Marshal(nativeCampaignControlWire{
		RequestID: control.RequestID, Action: control.Action,
		Reason: control.Reason, LeaseMS: control.LeaseMS, LeaseDeadline: control.LeaseDeadline,
	})
	if err != nil {
		r.mu.Lock()
		if current, still := r.pending[control.RequestID]; still && current == pending {
			r.resolvePendingLocked(control.RequestID, pending,
				fmt.Errorf("%w: cannot encode control frame", errNativeCampaignProtocolViolation))
		}
		r.mu.Unlock()
		return fmt.Errorf("%w: cannot encode control frame", errNativeCampaignProtocolViolation)
	}
	wire = append(wire, '\n')
	if err := r.enqueue(ctx, wire); err != nil {
		r.mu.Lock()
		if current, still := r.pending[control.RequestID]; still && current == pending {
			r.resolvePendingLocked(control.RequestID, pending, err)
		}
		r.mu.Unlock()
		return err
	}
	return r.waitPending(ctx, control.RequestID, pending, pending.done)
}

func (r *nativeCampaignProcessRunner) failTailDrain() {
	r.mu.Lock()
	if r.readerErr == nil {
		r.readerErr = errNativeCampaignProcessTailDrain
	}
	handle := r.handle
	r.mu.Unlock()
	// The process has naturally exited, so this is a local drain stop rather
	// than a cancel grace: broadcast stop to unblock the Events send and close
	// the owned pipes so a blocked reader can settle.
	r.stopOnce.Do(func() { close(r.stop) })
	r.closeStdin()
	if handle != nil {
		_ = handle.Kill()
		_ = handle.Close()
	}
}

func (r *nativeCampaignProcessRunner) deadlineLoop() {
	tailMode := false
	var tailDeadline time.Time
	processDone := r.processDone
	var readerDone <-chan struct{}
	for {
		r.mu.Lock()
		lease := r.leaseDeadline
		deadline := r.deadline
		expired := r.leaseExpired
		r.mu.Unlock()
		var next time.Time
		if tailMode {
			next = tailDeadline
		} else {
			next = deadline
			if !expired && !lease.IsZero() && (next.IsZero() || lease.Before(next)) {
				next = lease
			}
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !next.IsZero() {
			timer = time.NewTimer(time.Until(next))
			timerC = timer.C
		}
		select {
		case <-timerC:
			if tailMode {
				// Natural exit must not disable the deadline supervisor. If the
				// remaining tail cannot be delivered to Events within the common
				// deadline/drain cap, fail closed and release the reader.
				r.failTailDrain()
				return
			}
			now := time.Now()
			r.mu.Lock()
			if !now.Before(r.deadline) {
				r.deadlineHit = "execution_deadline"
				r.failPendingLocked(errNativeCampaignProcessDeadline)
				r.mu.Unlock()
				r.initiateCancel("execution_deadline")
				return
			}
			if !r.leaseExpired && !now.Before(r.leaseDeadline) {
				r.leaseExpired = true
				r.failPendingLocked(errNativeCampaignProcessLeaseExpired)
				r.mu.Unlock()
				r.initiateCancel("lease_expired")
				return
			}
			r.mu.Unlock()
		case <-r.leaseWake:
		case <-processDone:
			processDone = nil
			tailMode = true
			tailDeadline = time.Now().Add(nativeCampaignTailDrain)
			r.mu.Lock()
			deadline := r.deadline
			r.mu.Unlock()
			if !deadline.IsZero() && deadline.Before(tailDeadline) {
				tailDeadline = deadline
			}
			readerDone = r.readerDone
		case <-readerDone:
			return
		case <-r.stop:
			return
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (r *nativeCampaignProcessRunner) initiateCancel(reason string) {
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	handle := r.handle
	if handle == nil {
		r.mu.Unlock()
		return
	}
	requestID := r.start.RequestID + "-transport-cancel"
	if len(requestID) > 128 {
		requestID = "campaign-transport-cancel"
	}
	r.abandonLocked(requestID)
	r.mu.Unlock()
	wire, err := json.Marshal(nativeCampaignControlWire{
		RequestID: requestID, Action: "cancel", Reason: reason,
	})
	if err == nil {
		wire = append(wire, '\n')
		ctx, cancel := context.WithTimeout(context.Background(), nativeCampaignControlWriteTimeout)
		_ = r.enqueue(ctx, wire)
		cancel()
	}
	time.AfterFunc(nativeCampaignCancelGrace, r.killNow)
}

func (r *nativeCampaignProcessRunner) killNow() {
	r.mu.Lock()
	r.killRequested = true
	handle := r.handle
	r.mu.Unlock()
	r.stopOnce.Do(func() { close(r.stop) })
	r.closeStdin()
	if handle != nil {
		_ = handle.Kill()
	}
}

func (r *nativeCampaignProcessRunner) closeStdin() {
	r.stdinOnce.Do(func() { close(r.stdinStop) })
	r.stdinClosed.Do(func() {
		r.mu.Lock()
		handle := r.handle
		r.mu.Unlock()
		if handle != nil && handle.Stdin() != nil {
			_ = handle.Stdin().Close()
		}
	})
}

func (r *nativeCampaignProcessRunner) shutdown(immediate bool) {
	r.closeStdin()
	r.stopOnce.Do(func() { close(r.stop) })
	if immediate {
		r.killNow()
	}
}

func (r *nativeCampaignProcessRunner) Wait(ctx context.Context) (nativeCampaignRunnerFinal, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-r.done:
	case <-ctx.Done():
		r.shutdown(true)
		timer := time.NewTimer(nativeCampaignKillWait)
		select {
		case <-r.done:
		case <-timer.C:
		}
		timer.Stop()
		r.mu.Lock()
		final := r.final
		r.mu.Unlock()
		return final, ctx.Err()
	}
	r.mu.Lock()
	final := r.final
	seen := r.finalSeen
	readerErr := r.readerErr
	processErr := r.processErr
	deadlineHit := r.deadlineHit
	leaseExpired := r.leaseExpired
	r.mu.Unlock()
	if deadlineHit != "" {
		return final, fmt.Errorf("%w: %s", errNativeCampaignProcessDeadline, deadlineHit)
	}
	if leaseExpired {
		return final, errNativeCampaignProcessLeaseExpired
	}
	// Only this exact missing-final EOF symptom may yield to a confirmed
	// nonzero exit. Bad frames, truncation, limits and joined errors win.
	if readerErr != nil && !(readerErr == errNativeCampaignEOFWithoutFinal && processErr != nil) {
		return final, readerErr
	}
	if processErr != nil {
		return final, fmt.Errorf("%w: %v", errNativeCampaignProcessAbnormalExit, processErr)
	}
	if !seen {
		return final, fmt.Errorf("%w: no final frame", errNativeCampaignProtocolViolation)
	}
	plan, err := nativeCampaignPlanFromResources(r.start.OwnedResources)
	if err != nil {
		return final, err
	}
	if err = final.CreationSeal.validate(plan); err != nil {
		return final, fmt.Errorf("%w: %v", errNativeCampaignProtocolViolation, err)
	}
	// Only a successful complete stream/process result hands object bytes to storage.
	r.mu.Lock()
	final.CheckpointCorpus = make([]nativeCampaignCheckpointRecord, len(r.chunkRecords))
	for i, record := range r.chunkRecords {
		final.CheckpointCorpus[i] = record
		final.CheckpointCorpus[i].Data = append([]byte(nil), record.Data...)
	}
	r.mu.Unlock()
	return final, nil
}

func (r *nativeCampaignProcessRunner) validateCleanupRequest(req nativeCampaignCleanupRequest) error {
	if strings.TrimSpace(req.RequestID) == "" || len(req.RequestID) > 128 {
		return fmt.Errorf("%w: invalid cleanup request_id", errNativeCampaignProtocolViolation)
	}
	if req.TaskID != r.start.TaskID || req.CampaignID != r.start.CampaignID ||
		req.AttemptID != r.start.AttemptID || req.FencingToken != r.start.FencingToken {
		return fmt.Errorf("%w: cleanup request identity/fence does not match the started attempt", errNativeCampaignProtocolViolation)
	}
	if req.ResourcePlan != nil || req.CreationSeal != nil {
		if req.ResourcePlan == nil || req.CreationSeal == nil {
			return fmt.Errorf("%w: cleanup requires plan and seal", errNativeCampaignProtocolViolation)
		}
		if err := req.ResourcePlan.validate(req.TaskID, req.CampaignID, req.AttemptID, req.FencingToken); err != nil {
			return err
		}
		if err := req.CreationSeal.validate(req.ResourcePlan); err != nil {
			return err
		}
	}
	return nil
}

func (r *nativeCampaignProcessRunner) cleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	limit := 60 * time.Second
	if r.start.CleanupHardTimeoutMS >= 1000 && r.start.CleanupHardTimeoutMS <= 60000 {
		limit = time.Duration(r.start.CleanupHardTimeoutMS) * time.Millisecond
	}
	if limit > 60*time.Second {
		limit = 60 * time.Second
	}
	deadline := time.Now().Add(limit)
	if caller, ok := ctx.Deadline(); ok && caller.Before(deadline) {
		deadline = caller
	}
	return context.WithDeadline(ctx, deadline)
}

// ensureMainReaped is the gate between the campaign process and a success
// cleanup probe. The probe may only run after the transport's aggregate
// completion is confirmed; a killed-but-unreaped process can never be hidden by
// a successful probe. The wait is bounded by the shared cleanup deadline.
func (r *nativeCampaignProcessRunner) ensureMainReaped(ctx context.Context) error {
	r.mu.Lock()
	started := r.started
	r.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-r.done:
		return nil
	default:
	}
	r.shutdown(true)
	wait := nativeCampaignKillWait
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
	}
	if wait <= 0 {
		select {
		case <-r.done:
			return nil
		default:
		}
		return fmt.Errorf("%w: main process completion is unconfirmed", errNativeCampaignProcessUnreaped)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-r.done:
		return nil
	case <-timer.C:
		return fmt.Errorf("%w: main process did not terminate", errNativeCampaignProcessUnreaped)
	case <-ctx.Done():
		select {
		case <-r.done:
			return nil
		default:
		}
		return fmt.Errorf("%w: %v", errNativeCampaignProcessUnreaped, ctx.Err())
	}
}

func (r *nativeCampaignProcessRunner) Cleanup(ctx context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error) {
	report, err, _ := r.cleanup(ctx, req)
	return report, err
}

// The third result is the actual per-call ownership barrier, not the public
// deadline. Cleanup-only recovery waits for it before retiring its manager op.
func (r *nativeCampaignProcessRunner) cleanup(ctx context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error, <-chan struct{}) {
	completed := make(chan struct{})
	close(completed)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := r.validateCleanupRequest(req); err != nil {
		return nativeCampaignCleanupReport{}, err, completed
	}
	// One deadline covers main-process reaping, probe startup/IO and probe reap.
	// It is the earlier of the caller deadline and the cleanup hard limit (<=60s)
	// and is never restarted between phases.
	cleanupCtx, cancel := r.cleanupContext(ctx)
	if err := r.ensureMainReaped(cleanupCtx); err != nil {
		cancel()
		return nativeCampaignCleanupReport{}, err, completed
	}
	if err := cleanupCtx.Err(); err != nil {
		cancel()
		return nativeCampaignCleanupReport{}, err, completed
	}
	return r.runCleanupProbe(cleanupCtx, req, cancel)
}

type nativeCampaignProbeOutcome struct {
	report  nativeCampaignCleanupReport
	err     error
	waitErr error
}

func readNativeCampaignProbe(stdout io.Reader, expect nativeCampaignFrameExpectation) (nativeCampaignCleanupReport, error) {
	var report nativeCampaignCleanupReport
	br := bufio.NewReaderSize(stdout, 64<<10)
	var final *nativeCampaignCleanupReport
	var total int64
	for {
		line, terminated, err := readNativeCampaignProcessLine(br, NativeCampaignMaxFrameBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return report, err
		}
		if !terminated {
			return report, fmt.Errorf("%w: truncated cleanup probe frame", errNativeCampaignProtocolViolation)
		}
		total += int64(len(line)) + 1
		if total > NativeCampaignMaxEvidenceTotal {
			return report, errNativeCampaignEvidenceLimit
		}
		wire, err := decodeNativeCampaignWireFrame(line)
		if err != nil {
			return report, err
		}
		if final != nil {
			return report, fmt.Errorf("%w: cleanup probe emitted data after final", errNativeCampaignProtocolViolation)
		}
		if wire.Kind != "final" {
			return report, fmt.Errorf("%w: cleanup probe emitted non-final frame", errNativeCampaignProtocolViolation)
		}
		if wire.RequestID != expect.RequestID || wire.TaskID != expect.TaskID ||
			wire.CampaignID != expect.CampaignID || wire.AttemptID != expect.AttemptID ||
			wire.FencingToken != expect.FencingToken {
			return report, fmt.Errorf("%w: cleanup probe identity/fence does not match", errNativeCampaignProtocolViolation)
		}
		decoded := nativeCampaignCleanupReport{}
		if err := strictNativeCampaignUnmarshal(wire.Observation, &decoded); err != nil {
			return report, err
		}
		final = &decoded
	}
	if final == nil {
		return report, fmt.Errorf("%w: cleanup probe produced no final", errNativeCampaignProtocolViolation)
	}
	report = *final
	if len(report.Containers) > 64 || len(report.Errors) > 32 || report.ElapsedMS < 0 {
		return report, fmt.Errorf("%w: cleanup report exceeds bounds", errNativeCampaignProtocolViolation)
	}
	for _, container := range report.Containers {
		if len(container.Name) > 256 || len(container.State) > 32 {
			return report, fmt.Errorf("%w: cleanup container entry exceeds bounds", errNativeCampaignProtocolViolation)
		}
	}
	for _, message := range report.Errors {
		if len(message) > 512 {
			return report, fmt.Errorf("%w: cleanup error message exceeds bounds", errNativeCampaignProtocolViolation)
		}
	}
	return report, nil
}

func (r *nativeCampaignProcessRunner) drainProbeStderr(stderr io.Reader, done chan<- struct{}) {
	defer close(done)
	if stderr == nil {
		return
	}
	buf := make([]byte, 4096)
	for {
		n, err := stderr.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.probeStderr = append(r.probeStderr, buf[:n]...)
			if len(r.probeStderr) > nativeCampaignStderrMax {
				r.probeStderr = r.probeStderr[len(r.probeStderr)-nativeCampaignStderrMax:]
			}
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *nativeCampaignProcessRunner) runCleanupProbe(ctx context.Context, req nativeCampaignCleanupRequest, cancel context.CancelFunc) (nativeCampaignCleanupReport, error, <-chan struct{}) {
	defer cancel()
	done := make(chan struct{})
	frame, err := json.Marshal(nativeCampaignCleanupProbeWire{ResourcePlan: req.ResourcePlan, CreationSeal: req.CreationSeal, Operation: "campaign_cleanup_probe", RequestID: req.RequestID, TaskID: req.TaskID, CampaignID: req.CampaignID, AttemptID: req.AttemptID, FencingToken: req.FencingToken})
	if err != nil {
		cancel()
		close(done)
		return nativeCampaignCleanupReport{}, err, done
	}
	outcome := make(chan nativeCampaignProbeOutcome, 1)
	go func() {
		defer close(done)
		var out nativeCampaignProbeOutcome
		handle, startErr := r.cfg.Starter(nativeCampaignProcessSpec{Argv: append([]string(nil), r.cfg.Command...), Dir: r.cfg.Dir, Env: append([]string(nil), r.cfg.Env...)})
		if handle == nil {
			out.err = fmt.Errorf("%w: cannot start cleanup probe: %v", errNativeCampaignProtocolViolation, startErr)
			outcome <- out
			return
		}
		var killOnce, closeOnce sync.Once
		kill := func() { killOnce.Do(func() { _ = handle.Kill() }) }
		closeHandle := func() { closeOnce.Do(func() { _ = handle.Close() }) }
		r.mu.Lock()
		r.probeStderr = nil
		r.mu.Unlock()
		stderrDone := make(chan struct{})
		go r.drainProbeStderr(handle.Stderr(), stderrDone)
		ownerFinished := make(chan struct{})
		cancelDone := make(chan struct{})
		go func() {
			defer close(cancelDone)
			select {
			case <-ctx.Done():
				kill()
				closeHandle()
			case <-ownerFinished:
			}
		}()
		if startErr != nil {
			out.err = fmt.Errorf("%w: cannot start cleanup probe: %v", errNativeCampaignProtocolViolation, startErr)
		} else if ctx.Err() != nil {
			// A Starter returning after the shared deadline must never send a frame.
			out.err = ctx.Err()
		} else if err := writeNativeCampaignProbeFrame(handle, frame); err != nil {
			out.err = err
		} else {
			out.report, out.err = readNativeCampaignProbe(handle.Stdout(), nativeCampaignFrameExpectation{RequestID: req.RequestID, TaskID: req.TaskID, CampaignID: req.CampaignID, AttemptID: req.AttemptID, FencingToken: req.FencingToken})
		}
		if out.err != nil {
			kill()
		}
		// Exactly this owner calls Wait. The completion barrier includes Wait,
		// cancellation work, every reader and Close, even after caller timeout.
		out.waitErr = handle.Wait()
		closeHandle()
		close(ownerFinished)
		<-cancelDone
		<-stderrDone
		outcome <- out
	}()
	select {
	case out := <-outcome:
		if ctx.Err() != nil {
			return out.report, ctx.Err(), done
		}
		if out.err != nil {
			return out.report, out.err, done
		}
		if out.waitErr != nil {
			return out.report, fmt.Errorf("%w: cleanup probe exited abnormally: %v", errNativeCampaignProtocolViolation, out.waitErr), done
		}
		return out.report, nil, done
	case <-ctx.Done():
		return nativeCampaignCleanupReport{}, ctx.Err(), done
	}
}

func writeNativeCampaignProbeFrame(handle nativeCampaignProcessHandle, frame []byte) error {
	stdin := handle.Stdin()
	if stdin == nil {
		return fmt.Errorf("%w: cleanup probe stdin is unavailable", errNativeCampaignProtocolViolation)
	}
	for len(frame) > 0 {
		n, err := stdin.Write(frame)
		if n > 0 {
			frame = frame[n:]
		}
		if err != nil {
			return fmt.Errorf("%w: write cleanup probe frame: %v", errNativeCampaignProtocolViolation, err)
		}
		if n == 0 {
			return fmt.Errorf("%w: cleanup probe stdin made no progress", errNativeCampaignProtocolViolation)
		}
	}
	if _, err := stdin.Write([]byte("\n")); err != nil {
		return fmt.Errorf("%w: terminate cleanup probe frame: %v", errNativeCampaignProtocolViolation, err)
	}
	return stdin.Close()
}

// A cleanup-only capability constructs transport state but never invokes Start.
// Backend selection remains explicit in the supplied process configuration.
func newNativeCampaignCleanupProbe(cfg nativeCampaignProcessConfig) nativeCampaignCleanupProbe {
	normalized := cfg.normalized()
	return func(ctx context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error) {
		runner := newNativeCampaignProcessRunner(normalized, nativeCampaignRunnerStart{TaskID: req.TaskID, CampaignID: req.CampaignID, AttemptID: req.AttemptID, FencingToken: req.FencingToken, CleanupHardTimeoutMS: 60000})
		report, err, done := runner.cleanup(ctx, req)
		<-done
		if err == nil && !report.verifiedFor(req.ResourcePlan, req.CreationSeal) {
			return report, errors.New("cleanup report is not bound to the sealed resource set")
		}
		return report, err
	}
}
