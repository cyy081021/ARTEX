package db

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Native Campaign v1 (T2) data model and safe, task-scoped reads/basic creates.
//
// This file deliberately contains no campaign/attempt state machine, scheduler,
// runner, budget claim or HTTP API. Those belong to later batches. Every read
// below is scoped by task_id and bounded; JSON fields are normalized to compact
// UTF-8 bytes in the application before they reach PostgreSQL.

const (
	NativeCampaignWorkerSlot = "local-afl-1"
	NativeCampaignSpecBytes  = 262144
)

var nativeCampaignSHA256Pattern = func() func(string) bool {
	return func(v string) bool {
		if len(v) != 64 {
			return false
		}
		for i := 0; i < len(v); i++ {
			c := v[i]
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
		return true
	}
}()

type NativeCampaign struct {
	ID                 int64           `json:"id"`
	TaskID             int64           `json:"task_id"`
	ArtifactID         int64           `json:"artifact_id"`
	CreatorKind        string          `json:"creator_kind"`
	CreatorID          int64           `json:"creator_id"`
	SpecVersion        int             `json:"spec_version"`
	Spec               json.RawMessage `json:"spec"`
	SpecHash           string          `json:"spec_hash"`
	ArtifactSHA256     string          `json:"artifact_sha256"`
	ProfileID          string          `json:"profile_id"`
	ImageDigest        string          `json:"image_digest"`
	ImageID            *string         `json:"image_id"`
	PolicyRevision     int64           `json:"policy_revision"`
	ConfigRevision     int64           `json:"config_revision"`
	State              string          `json:"state"`
	DesiredState       string          `json:"desired_state"`
	StateVersion       int64           `json:"state_version"`
	TotalBudgetMS      int64           `json:"total_budget_ms"`
	ChargedBudgetMS    int64           `json:"charged_budget_ms"`
	CurrentAttemptID   *int64          `json:"current_attempt_id"`
	LatestCheckpointID *int64          `json:"latest_checkpoint_id"`
	CleanupStatus      string          `json:"cleanup_status"`
	PauseOrigin        string          `json:"pause_origin"`
	TerminationReason  *string         `json:"termination_reason"`
	LastErrorCode      *string         `json:"last_error_code"`
	LastErrorMessage   *string         `json:"last_error_message"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
	StartedAt          *time.Time      `json:"started_at"`
	EndedAt            *time.Time      `json:"ended_at"`
}

type NativeCampaignInput struct {
	TaskID         int64
	ArtifactID     int64
	CreatorKind    string
	CreatorID      int64
	Spec           json.RawMessage
	SpecHash       string
	ArtifactSHA256 string
	ProfileID      string
	ImageDigest    string
	ImageID        string
	PolicyRevision int64
	ConfigRevision int64
	TotalBudgetMS  int64
}

type NativeCampaignAttempt struct {
	ID                 int64           `json:"id"`
	TaskID             int64           `json:"task_id"`
	CampaignID         int64           `json:"campaign_id"`
	AttemptNo          int             `json:"attempt_no"`
	NativeRunID        int64           `json:"native_run_id"`
	RuntimeRunID       int64           `json:"runtime_run_id"`
	WorkerSlot         string          `json:"worker_slot"`
	LeaseOwner         string          `json:"lease_owner"`
	LeaseInstance      string          `json:"lease_instance"`
	FencingToken       int64           `json:"fencing_token"`
	LeaseExpiresAt     time.Time       `json:"lease_expires_at"`
	State              string          `json:"state"`
	Phase              string          `json:"phase"`
	ReservedBudgetMS   int64           `json:"reserved_budget_ms"`
	ChargedBudgetMS    int64           `json:"charged_budget_ms"`
	OperatorKind       string          `json:"operator_kind"`
	OperatorID         int64           `json:"operator_id"`
	StartedAt          *time.Time      `json:"started_at"`
	EndedAt            *time.Time      `json:"ended_at"`
	TerminationReason  *string         `json:"termination_reason"`
	CleanupStatus      string          `json:"cleanup_status"`
	ResourceHold       bool            `json:"resource_hold"`
	HoldReason         *string         `json:"hold_reason"`
	ActualElapsedMS    int64           `json:"actual_elapsed_ms"`
	CleanupOverrunMS   int64           `json:"cleanup_overrun_ms"`
	CheckpointID       *int64          `json:"checkpoint_id"`
	EvidenceManifestID *int64          `json:"evidence_manifest_id"`
	OwnedResources     json.RawMessage `json:"owned_resources"`
	BudgetOverrun      bool            `json:"budget_overrun"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

type NativeCampaignAttemptInput struct {
	TaskID           int64
	CampaignID       int64
	AttemptNo        int
	NativeRunID      int64
	RuntimeRunID     int64
	LeaseInstance    string
	LeaseExpiresAt   time.Time
	ReservedBudgetMS int64
	OperatorKind     string
	OperatorID       int64
}

type NativeCampaignObject struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"`
	SHA256     string    `json:"sha256"`
	Length     int64     `json:"length"`
	StorageKey string    `json:"storage_key"`
	CreatedAt  time.Time `json:"created_at"`
}

type NativeCampaignObjectInput struct {
	TaskID     int64
	SHA256     string
	Length     int64
	StorageKey string
}

type NativeCampaignCorpusManifest struct {
	ID             int64     `json:"id"`
	TaskID         int64     `json:"task_id"`
	CampaignID     int64     `json:"campaign_id"`
	AttemptID      int64     `json:"attempt_id"`
	FormatVersion  int       `json:"format_version"`
	ManifestSHA256 string    `json:"manifest_sha256"`
	EntryCount     int       `json:"entry_count"`
	TotalBytes     int64     `json:"total_bytes"`
	Truncated      bool      `json:"truncated"`
	CreatedAt      time.Time `json:"created_at"`
}

type NativeCampaignCorpusEntry struct {
	ID         int64  `json:"id"`
	TaskID     int64  `json:"task_id"`
	ManifestID int64  `json:"manifest_id"`
	Ordinal    int    `json:"ordinal"`
	ObjectID   int64  `json:"object_id"`
	SHA256     string `json:"sha256"`
	Length     int64  `json:"length"`
	StorageKey string `json:"storage_key"`
	SourceType string `json:"source_type"`
	SourceRef  string `json:"source_ref"`
}

type NativeCampaignEntryInput struct {
	Ordinal    int
	ObjectID   int64
	SHA256     string
	Length     int64
	StorageKey string
	SourceType string
	SourceRef  string
}

type NativeCampaignManifestInput struct {
	TaskID         int64
	CampaignID     int64
	AttemptID      int64
	ManifestSHA256 string
	EntryCount     int
	TotalBytes     int64
	Truncated      bool
	Entries        []NativeCampaignEntryInput
}

type NativeCampaignCheckpoint struct {
	ID            int64      `json:"id"`
	TaskID        int64      `json:"task_id"`
	CampaignID    int64      `json:"campaign_id"`
	AttemptID     int64      `json:"attempt_id"`
	ManifestID    int64      `json:"manifest_id"`
	State         string     `json:"state"`
	FormatVersion int        `json:"format_version"`
	EntryCount    int        `json:"entry_count"`
	TotalBytes    int64      `json:"total_bytes"`
	Truncated     bool       `json:"truncated"`
	CreatedAt     time.Time  `json:"created_at"`
	VerifiedAt    *time.Time `json:"verified_at"`
}

type NativeCampaignCheckpointInput struct {
	TaskID     int64
	CampaignID int64
	AttemptID  int64
	ManifestID int64
	EntryCount int
	TotalBytes int64
	Truncated  bool
}

type NativeCampaignEvidence struct {
	ID          int64           `json:"id"`
	TaskID      int64           `json:"task_id"`
	CampaignID  int64           `json:"campaign_id"`
	AttemptID   int64           `json:"attempt_id"`
	Kind        string          `json:"kind"`
	Operation   string          `json:"operation"`
	Authority   string          `json:"authority"`
	ResultPath  string          `json:"result_path"`
	SHA256      string          `json:"sha256"`
	Observation json.RawMessage `json:"observation"`
	Truncated   bool            `json:"truncated"`
	CreatedAt   time.Time       `json:"created_at"`
}

type NativeCampaignEvidenceInput struct {
	TaskID      int64
	CampaignID  int64
	AttemptID   int64
	Kind        string
	ResultPath  string
	SHA256      string
	Observation json.RawMessage
	Truncated   bool
}

type NativeCampaignEvent struct {
	ID         int64           `json:"id"`
	TaskID     int64           `json:"task_id"`
	CampaignID int64           `json:"campaign_id"`
	AttemptID  *int64          `json:"attempt_id"`
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  time.Time       `json:"created_at"`
}

type NativeCampaignEventInput struct {
	TaskID     int64
	CampaignID int64
	AttemptID  *int64
	Kind       string
	Payload    json.RawMessage
}

type NativeCampaignRequest struct {
	ID             int64           `json:"id"`
	TaskID         int64           `json:"task_id"`
	CampaignID     *int64          `json:"campaign_id"`
	RequestID      string          `json:"request_id"`
	Action         string          `json:"action"`
	RequestHash    string          `json:"request_hash"`
	ResponseStatus int             `json:"response_status"`
	ResponseBody   json.RawMessage `json:"response_body"`
	CreatedAt      time.Time       `json:"created_at"`
}

type NativeCampaignRequestInput struct {
	TaskID         int64
	CampaignID     *int64
	RequestID      string
	Action         string
	RequestHash    string
	ResponseStatus int
	ResponseBody   json.RawMessage
}

func normalizeNativeCampaignJSONObject(raw json.RawMessage, maxBytes int, field string) ([]byte, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("%s is required", field)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", field, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("%s has trailing JSON data", field)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	canonical, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be encoded: %w", field, err)
	}
	if len(canonical) > maxBytes {
		return nil, fmt.Errorf("%s exceeds %d canonical UTF-8 bytes", field, maxBytes)
	}
	return canonical, nil
}

func validateNativeCampaignSHA256(v, field string) error {
	if !nativeCampaignSHA256Pattern(v) {
		return fmt.Errorf("%s must be 64 lowercase hex characters", field)
	}
	return nil
}

func nativeCampaignStorageKey(taskID int64, sha string) string {
	return fmt.Sprintf("tasks/%d/reverse/campaigns/objects/sha256/%s/%s", taskID, sha[:2], sha)
}

func validNativeCampaignRequestID(v string) bool {
	if len(v) < 1 || len(v) > 128 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

func validNativeCampaignResultPath(taskID int64, p string) bool {
	if len(p) < 1 || len(p) > 512 || strings.ContainsAny(p, "\\\x00") {
		return false
	}
	if !strings.HasPrefix(p, fmt.Sprintf("tasks/%d/", taskID)) {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func clampNativeCampaignLimit(limit int) int {
	if limit <= 0 {
		return 50
	}
	if limit > 200 {
		return 200
	}
	return limit
}

func scanNativeCampaignList[T any](rows *sql.Rows, err error) ([]T, error) {
	out := []T{}
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if e := rows.Scan(&raw); e != nil {
			return nil, e
		}
		var value T
		if e := json.Unmarshal(raw, &value); e != nil {
			return nil, e
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (d *DB) scanNativeCampaignRow(row interface{ Scan(...any) error }) (*NativeCampaign, error) {
	var raw []byte
	if err := row.Scan(&raw); err != nil {
		return nil, err
	}
	var value NativeCampaign
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return &value, nil
}

func (d *DB) CreateNativeCampaign(ctx context.Context, in NativeCampaignInput) (*NativeCampaign, error) {
	if in.TaskID <= 0 || in.ArtifactID <= 0 {
		return nil, errors.New("task_id and artifact_id are required")
	}
	artifact, err := d.GetReverseArtifact(in.TaskID, in.ArtifactID)
	if err != nil {
		return nil, err
	}
	if artifact == nil {
		return nil, errors.New("artifact does not belong to task")
	}
	if artifact.SHA256 != in.ArtifactSHA256 {
		return nil, errors.New("artifact_sha256 does not match the task artifact")
	}
	if err = validateNativeCampaignSHA256(in.ArtifactSHA256, "artifact_sha256"); err != nil {
		return nil, err
	}
	if err = validateNativeCampaignSHA256(in.SpecHash, "spec_hash"); err != nil {
		return nil, err
	}
	spec, err := normalizeNativeCampaignJSONObject(in.Spec, NativeCampaignSpecBytes, "spec")
	if err != nil {
		return nil, err
	}
	if in.CreatorKind == "" {
		in.CreatorKind = "admin"
	}
	if (in.CreatorKind == "admin" && in.CreatorID != 0) ||
		(in.CreatorKind == "intent" && in.CreatorID <= 0) ||
		(in.CreatorKind != "admin" && in.CreatorKind != "intent") {
		return nil, errors.New("invalid creator_kind/creator_id")
	}
	in.ProfileID = strings.TrimSpace(in.ProfileID)
	if len(in.ProfileID) < 1 || len(in.ProfileID) > 64 {
		return nil, errors.New("profile_id must be 1..64 characters")
	}
	in.ImageDigest = strings.TrimSpace(in.ImageDigest)
	if len(in.ImageDigest) < 1 || len(in.ImageDigest) > 512 {
		return nil, errors.New("image_digest must be 1..512 characters")
	}
	if in.ImageID != "" {
		if len(in.ImageID) != len("sha256:")+64 || !strings.HasPrefix(in.ImageID, "sha256:") ||
			!nativeCampaignSHA256Pattern(in.ImageID[len("sha256:"):]) {
			return nil, errors.New("image_id must be empty or sha256:<64 lowercase hex>")
		}
	}
	if in.PolicyRevision < 1 || in.ConfigRevision < 1 {
		return nil, errors.New("policy_revision and config_revision must be >= 1")
	}
	if in.TotalBudgetMS < 6000 || in.TotalBudgetMS > 86400000 {
		return nil, errors.New("total_budget_ms must be between 6000 and 86400000")
	}
	var imageID any
	if in.ImageID != "" {
		imageID = in.ImageID
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH c AS (
		INSERT INTO native_campaigns(
			task_id,artifact_id,creator_kind,creator_id,spec,spec_hash,artifact_sha256,
			profile_id,image_digest,image_id,policy_revision,config_revision,total_budget_ms)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING *) SELECT row_to_json(c) FROM c`,
		in.TaskID, in.ArtifactID, in.CreatorKind, in.CreatorID, spec, in.SpecHash,
		in.ArtifactSHA256, in.ProfileID, in.ImageDigest, imageID,
		in.PolicyRevision, in.ConfigRevision, in.TotalBudgetMS).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaign
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaign(ctx context.Context, taskID, id int64) (*NativeCampaign, error) {
	if taskID <= 0 || id <= 0 {
		return nil, errors.New("task_id and campaign id are required")
	}
	return d.scanNativeCampaignRow(d.QueryRowContext(ctx,
		`SELECT row_to_json(c) FROM native_campaigns c WHERE task_id=$1 AND id=$2`, taskID, id))
}

func (d *DB) NativeCampaigns(ctx context.Context, taskID int64, limit int, beforeID int64) ([]NativeCampaign, error) {
	if taskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaign](d.QueryContext(ctx,
		`SELECT row_to_json(c) FROM native_campaigns c
		 WHERE task_id=$1 AND ($3=0 OR id<$3) ORDER BY id DESC LIMIT $2`,
		taskID, limit, beforeID))
}

func (d *DB) CreateNativeCampaignAttempt(ctx context.Context, in NativeCampaignAttemptInput) (*NativeCampaignAttempt, error) {
	if in.TaskID <= 0 || in.CampaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	if in.AttemptNo < 1 || in.AttemptNo > 1000 {
		return nil, errors.New("attempt_no must be between 1 and 1000")
	}
	if in.NativeRunID <= 0 || in.RuntimeRunID <= 0 {
		return nil, errors.New("native_run_id and runtime_run_id are required")
	}
	if in.NativeRunID != in.RuntimeRunID {
		return nil, errors.New("native_run_id and runtime_run_id must identify the same actual run")
	}
	if len(in.LeaseInstance) < 1 || len(in.LeaseInstance) > 128 {
		return nil, errors.New("lease_instance must be 1..128 characters")
	}
	if in.LeaseExpiresAt.IsZero() {
		return nil, errors.New("lease_expires_at is required")
	}
	if in.ReservedBudgetMS < 6000 || in.ReservedBudgetMS > 900000 {
		return nil, errors.New("reserved_budget_ms must be between 6000 and 900000")
	}
	if in.OperatorKind == "" {
		in.OperatorKind = "admin"
	}
	if (in.OperatorKind == "admin" && in.OperatorID != 0) ||
		(in.OperatorKind == "intent" && in.OperatorID <= 0) ||
		(in.OperatorKind != "admin" && in.OperatorKind != "intent") {
		return nil, errors.New("invalid operator_kind/operator_id")
	}
	if _, err := d.reverseTask(in.TaskID); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, in.TaskID, in.CampaignID); err != nil {
		return nil, err
	}

	var campaignTask int64
	if err = tx.QueryRowContext(ctx,
		`SELECT task_id FROM native_campaigns WHERE id=$1 AND task_id=$2`,
		in.CampaignID, in.TaskID).Scan(&campaignTask); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("campaign does not belong to task")
		}
		return nil, err
	}
	var mode string
	if err = tx.QueryRowContext(ctx,
		`SELECT mode FROM reverse_native_runs WHERE run_id=$1 AND task_id=$2`,
		in.NativeRunID, in.TaskID).Scan(&mode); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("native run does not belong to task")
		}
		return nil, err
	}
	if mode != NativeModeCampaign {
		return nil, errors.New("native run must use campaign mode")
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH a AS (
		INSERT INTO native_campaign_attempts(
			task_id,campaign_id,attempt_no,native_run_id,runtime_run_id,
			worker_slot,lease_owner,lease_instance,lease_expires_at,
			state,phase,reserved_budget_ms,operator_kind,operator_id,
			cleanup_status,resource_hold,hold_reason)
		VALUES($1,$2,$3,$4,$5,$6,$6,$7,$8,'claimed','preflight',$9,$10,$11,
			'pending',true,'active')
		RETURNING *) SELECT row_to_json(a) FROM a`,
		in.TaskID, in.CampaignID, in.AttemptNo, in.NativeRunID, in.RuntimeRunID,
		NativeCampaignWorkerSlot, in.LeaseInstance, in.LeaseExpiresAt,
		in.ReservedBudgetMS, in.OperatorKind, in.OperatorID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	var out NativeCampaignAttempt
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignAttempt(ctx context.Context, taskID, id int64) (*NativeCampaignAttempt, error) {
	if taskID <= 0 || id <= 0 {
		return nil, errors.New("task_id and attempt id are required")
	}
	var raw []byte
	if err := d.QueryRowContext(ctx,
		`SELECT row_to_json(a) FROM native_campaign_attempts a WHERE task_id=$1 AND id=$2`,
		taskID, id).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignAttempt
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignAttempts(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignAttempt, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignAttempt](d.QueryContext(ctx,
		`SELECT row_to_json(a) FROM native_campaign_attempts a
		 WHERE task_id=$1 AND campaign_id=$2 AND ($4=0 OR id<$4)
		 ORDER BY id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

func (d *DB) CreateNativeCampaignObject(ctx context.Context, in NativeCampaignObjectInput) (*NativeCampaignObject, error) {
	if in.TaskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	if err := validateNativeCampaignSHA256(in.SHA256, "sha256"); err != nil {
		return nil, err
	}
	if in.Length < 1 || in.Length > 4096 {
		return nil, errors.New("object length must be between 1 and 4096")
	}
	expected := nativeCampaignStorageKey(in.TaskID, in.SHA256)
	if in.StorageKey == "" {
		in.StorageKey = expected
	}
	if in.StorageKey != expected {
		return nil, errors.New("storage_key does not match the task/content-addressed path")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH o AS (
		INSERT INTO native_campaign_objects(task_id,sha256,length,storage_key)
		VALUES($1,$2,$3,$4)
		ON CONFLICT (task_id,sha256,length) DO NOTHING
		RETURNING *) SELECT row_to_json(o) FROM o`,
		in.TaskID, in.SHA256, in.Length, in.StorageKey).Scan(&raw)
	if err == nil {
		var out NativeCampaignObject
		if err = json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &out, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var existing NativeCampaignObject
	if err = tx.QueryRowContext(ctx,
		`SELECT row_to_json(o) FROM native_campaign_objects o
		 WHERE task_id=$1 AND sha256=$2 AND length=$3`,
		in.TaskID, in.SHA256, in.Length).Scan(&raw); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &existing); err != nil {
		return nil, err
	}
	if existing.StorageKey != expected {
		return nil, errors.New("existing object has a conflicting storage key")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &existing, nil
}

func (d *DB) NativeCampaignObject(ctx context.Context, taskID, id int64) (*NativeCampaignObject, error) {
	if taskID <= 0 || id <= 0 {
		return nil, errors.New("task_id and object id are required")
	}
	var raw []byte
	if err := d.QueryRowContext(ctx,
		`SELECT row_to_json(o) FROM native_campaign_objects o WHERE task_id=$1 AND id=$2`,
		taskID, id).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignObject
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignObjects(ctx context.Context, taskID int64, limit int, beforeID int64) ([]NativeCampaignObject, error) {
	if taskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignObject](d.QueryContext(ctx,
		`SELECT row_to_json(o) FROM native_campaign_objects o
		 WHERE task_id=$1 AND ($3=0 OR id<$3) ORDER BY id DESC LIMIT $2`,
		taskID, limit, beforeID))
}

func validateNativeCampaignManifestInput(in *NativeCampaignManifestInput, requireObjectIDs bool) error {
	if in.TaskID <= 0 || in.CampaignID <= 0 || in.AttemptID <= 0 {
		return errors.New("task_id, campaign_id and attempt_id are required")
	}
	if err := validateNativeCampaignSHA256(in.ManifestSHA256, "manifest_sha256"); err != nil {
		return err
	}
	if in.EntryCount < 1 || in.EntryCount > 512 || in.EntryCount != len(in.Entries) {
		return errors.New("entry_count must equal 1..512 entries")
	}
	if in.TotalBytes < 1 || in.TotalBytes > 1048576 {
		return errors.New("total_bytes must be between 1 and 1048576")
	}
	ordinals := make(map[int]struct{}, len(in.Entries))
	var sum int64
	for i := range in.Entries {
		entry := &in.Entries[i]
		if entry.Ordinal < 0 || entry.Ordinal > 511 {
			return errors.New("entry ordinal must be between 0 and 511")
		}
		if _, exists := ordinals[entry.Ordinal]; exists {
			return errors.New("entry ordinals must be unique")
		}
		ordinals[entry.Ordinal] = struct{}{}
		if requireObjectIDs && entry.ObjectID <= 0 {
			return errors.New("entry object_id is required")
		}
		if err := validateNativeCampaignSHA256(entry.SHA256, "entry sha256"); err != nil {
			return err
		}
		if entry.Length < 1 || entry.Length > 4096 {
			return errors.New("entry length must be between 1 and 4096")
		}
		expected := nativeCampaignStorageKey(in.TaskID, entry.SHA256)
		if entry.StorageKey != "" && entry.StorageKey != expected {
			return errors.New("entry storage_key does not match the task/content-addressed path")
		}
		entry.StorageKey = expected
		if entry.SourceType != "seed" && entry.SourceType != "queue" &&
			entry.SourceType != "crash" && entry.SourceType != "import" {
			return errors.New("invalid entry source_type")
		}
		if len(entry.SourceRef) > 256 {
			return errors.New("entry source_ref exceeds 256 characters")
		}
		sum += entry.Length
	}
	if sum != in.TotalBytes {
		return errors.New("total_bytes must equal the sum of entry lengths")
	}
	return nil
}

func (d *DB) CreateNativeCampaignManifest(ctx context.Context, in NativeCampaignManifestInput) (*NativeCampaignCorpusManifest, error) {
	if err := validateNativeCampaignManifestInput(&in, true); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var raw []byte
	if err = tx.QueryRowContext(ctx, `WITH m AS (
		INSERT INTO native_campaign_corpus_manifests(
			task_id,campaign_id,attempt_id,manifest_sha256,entry_count,total_bytes,truncated)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		RETURNING *) SELECT row_to_json(m) FROM m`,
		in.TaskID, in.CampaignID, in.AttemptID, in.ManifestSHA256,
		in.EntryCount, in.TotalBytes, in.Truncated).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignCorpusManifest
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	for _, entry := range in.Entries {
		if _, err = tx.ExecContext(ctx, `INSERT INTO native_campaign_corpus_entries(
			task_id,manifest_id,ordinal,object_id,sha256,length,storage_key,source_type,source_ref)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			in.TaskID, out.ID, entry.Ordinal, entry.ObjectID, entry.SHA256,
			entry.Length, entry.StorageKey, entry.SourceType, entry.SourceRef); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignManifest(ctx context.Context, taskID, id int64) (*NativeCampaignCorpusManifest, error) {
	if taskID <= 0 || id <= 0 {
		return nil, errors.New("task_id and manifest id are required")
	}
	var raw []byte
	if err := d.QueryRowContext(ctx,
		`SELECT row_to_json(m) FROM native_campaign_corpus_manifests m
		 WHERE task_id=$1 AND id=$2`, taskID, id).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignCorpusManifest
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignManifests(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignCorpusManifest, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignCorpusManifest](d.QueryContext(ctx,
		`SELECT row_to_json(m) FROM native_campaign_corpus_manifests m
		 WHERE task_id=$1 AND campaign_id=$2 AND ($4=0 OR id<$4)
		 ORDER BY id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

func (d *DB) NativeCampaignEntries(ctx context.Context, taskID, manifestID int64) ([]NativeCampaignCorpusEntry, error) {
	if taskID <= 0 || manifestID <= 0 {
		return nil, errors.New("task_id and manifest_id are required")
	}
	return scanNativeCampaignList[NativeCampaignCorpusEntry](d.QueryContext(ctx,
		`SELECT row_to_json(e) FROM native_campaign_corpus_entries e
		 WHERE task_id=$1 AND manifest_id=$2 ORDER BY ordinal LIMIT 512`,
		taskID, manifestID))
}

func (d *DB) CreateNativeCampaignCheckpoint(ctx context.Context, in NativeCampaignCheckpointInput) (*NativeCampaignCheckpoint, error) {
	if in.TaskID <= 0 || in.CampaignID <= 0 || in.AttemptID <= 0 || in.ManifestID <= 0 {
		return nil, errors.New("task_id, campaign_id, attempt_id and manifest_id are required")
	}
	if in.EntryCount < 1 || in.EntryCount > 512 {
		return nil, errors.New("entry_count must be between 1 and 512")
	}
	if in.TotalBytes < 1 || in.TotalBytes > 1048576 {
		return nil, errors.New("total_bytes must be between 1 and 1048576")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var entryCount int
	var totalBytes int64
	var truncated bool
	if err = tx.QueryRowContext(ctx,
		`SELECT entry_count,total_bytes,truncated FROM native_campaign_corpus_manifests
		 WHERE id=$1 AND task_id=$2 AND campaign_id=$3 AND attempt_id=$4`,
		in.ManifestID, in.TaskID, in.CampaignID, in.AttemptID).
		Scan(&entryCount, &totalBytes, &truncated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("manifest does not belong to this campaign attempt")
		}
		return nil, err
	}
	if entryCount != in.EntryCount || totalBytes != in.TotalBytes || truncated != in.Truncated {
		return nil, errors.New("checkpoint counts do not match the derived manifest")
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH c AS (
		INSERT INTO native_campaign_checkpoints(
			task_id,campaign_id,attempt_id,manifest_id,state,entry_count,total_bytes,truncated)
		VALUES($1,$2,$3,$4,'staging',$5,$6,$7)
		RETURNING *) SELECT row_to_json(c) FROM c`,
		in.TaskID, in.CampaignID, in.AttemptID, in.ManifestID,
		in.EntryCount, in.TotalBytes, in.Truncated).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	var out NativeCampaignCheckpoint
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignCheckpoint(ctx context.Context, taskID, id int64) (*NativeCampaignCheckpoint, error) {
	if taskID <= 0 || id <= 0 {
		return nil, errors.New("task_id and checkpoint id are required")
	}
	var raw []byte
	if err := d.QueryRowContext(ctx,
		`SELECT row_to_json(c) FROM native_campaign_checkpoints c
		 WHERE task_id=$1 AND id=$2`, taskID, id).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignCheckpoint
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignCheckpoints(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignCheckpoint, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignCheckpoint](d.QueryContext(ctx,
		`SELECT row_to_json(c) FROM native_campaign_checkpoints c
		 WHERE task_id=$1 AND campaign_id=$2 AND ($4=0 OR id<$4)
		 ORDER BY id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

func (d *DB) CreateNativeCampaignEvidence(ctx context.Context, in NativeCampaignEvidenceInput) (*NativeCampaignEvidence, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	out, err := insertNativeCampaignEvidenceTx(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func insertNativeCampaignEvidenceTx(ctx context.Context, tx *sql.Tx, in NativeCampaignEvidenceInput) (*NativeCampaignEvidence, error) {
	if in.TaskID <= 0 || in.CampaignID <= 0 || in.AttemptID <= 0 {
		return nil, errors.New("task_id, campaign_id and attempt_id are required")
	}
	switch in.Kind {
	case "attempt_final", "checkpoint", "pause", "cancel", "interrupt":
	default:
		return nil, errors.New("invalid evidence kind")
	}
	if !validNativeCampaignResultPath(in.TaskID, in.ResultPath) {
		return nil, errors.New("result_path must be a bounded task-scoped relative path")
	}
	if err := validateNativeCampaignSHA256(in.SHA256, "sha256"); err != nil {
		return nil, err
	}
	observation, err := normalizeNativeCampaignJSONObject(in.Observation, 262144, "observation")
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH e AS (
		INSERT INTO native_campaign_evidence(
			task_id,campaign_id,attempt_id,kind,result_path,sha256,observation,truncated)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING *) SELECT row_to_json(e) FROM e`,
		in.TaskID, in.CampaignID, in.AttemptID, in.Kind, in.ResultPath,
		in.SHA256, observation, in.Truncated).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaignEvidence
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignEvidenceList(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignEvidence, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignEvidence](d.QueryContext(ctx,
		`SELECT row_to_json(e) FROM native_campaign_evidence e
		 WHERE task_id=$1 AND campaign_id=$2 AND ($4=0 OR id<$4)
		 ORDER BY id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

func (d *DB) CreateNativeCampaignEvent(ctx context.Context, in NativeCampaignEventInput) (*NativeCampaignEvent, error) {
	if in.Kind == nativeCampaignArchiveRestoredEvent {
		return nil, nativeCampaignErrorf("invalid_request", 400, "reserved archive event")
	}
	if in.TaskID <= 0 || in.CampaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	if len(in.Kind) < 1 || len(in.Kind) > 64 {
		return nil, errors.New("event kind must be 1..64 characters")
	}
	payload, err := normalizeNativeCampaignJSONObject(in.Payload, 16384, "payload")
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH e AS (
		INSERT INTO native_campaign_events(task_id,campaign_id,attempt_id,kind,payload)
		VALUES($1,$2,$3,$4,$5)
		RETURNING *) SELECT row_to_json(e) FROM e`,
		in.TaskID, in.CampaignID, in.AttemptID, in.Kind, payload).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaignEvent
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignEvents(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignEvent, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignEvent](d.QueryContext(ctx,
		`SELECT row_to_json(e) FROM native_campaign_events e
		 WHERE task_id=$1 AND campaign_id=$2 AND ($4=0 OR id<$4)
		 ORDER BY id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

func (d *DB) CreateNativeCampaignRequest(ctx context.Context, in NativeCampaignRequestInput) (*NativeCampaignRequest, error) {
	if in.TaskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	if !validNativeCampaignRequestID(in.RequestID) {
		return nil, errors.New("request_id must be 1..128 visible ASCII characters")
	}
	switch in.Action {
	case "create", "validate", "start", "status", "list", "pause", "cancel", "resume", "export_manifest":
	default:
		return nil, errors.New("invalid campaign action")
	}
	if err := validateNativeCampaignSHA256(in.RequestHash, "request_hash"); err != nil {
		return nil, err
	}
	if in.ResponseStatus < 200 || in.ResponseStatus > 499 {
		return nil, errors.New("response_status must be between 200 and 499")
	}
	body, err := normalizeNativeCampaignJSONObject(in.ResponseBody, 65536, "response_body")
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if err := admitNativeCampaignWriteTx(ctx, tx, in.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}

	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH r AS (
		INSERT INTO native_campaign_requests(
			task_id,campaign_id,request_id,action,request_hash,response_status,response_body)
		VALUES($1,$2,$3,$4,$5,$6,$7)
		RETURNING *) SELECT row_to_json(r) FROM r`,
		in.TaskID, in.CampaignID, in.RequestID, in.Action, in.RequestHash,
		in.ResponseStatus, body).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaignRequest
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignRequest(ctx context.Context, taskID int64, requestID string) (*NativeCampaignRequest, error) {
	if taskID <= 0 || !validNativeCampaignRequestID(requestID) {
		return nil, errors.New("task_id and request_id are required")
	}
	var raw []byte
	if err := d.QueryRowContext(ctx,
		`SELECT row_to_json(r) FROM native_campaign_requests r
		 WHERE task_id=$1 AND request_id=$2`, taskID, requestID).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignRequest
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (d *DB) NativeCampaignRequests(ctx context.Context, taskID int64, limit int, beforeID int64) ([]NativeCampaignRequest, error) {
	if taskID <= 0 {
		return nil, errors.New("task_id is required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignRequest](d.QueryContext(ctx,
		`SELECT row_to_json(r) FROM native_campaign_requests r
		 WHERE task_id=$1 AND ($3=0 OR id<$3) ORDER BY id DESC LIMIT $2`,
		taskID, limit, beforeID))
}

// ---------------------------------------------------------------------------
// T3 shared types. These are deliberately passive: they only describe errors,
// explicit authorization inputs, and idempotent command responses. No method in
// this file changes the T2 read/create behavior above.
// ---------------------------------------------------------------------------

// NativeCampaignError is the stable application-facing error used by the pure
// state-machine/budget transaction APIs. Code is the wire code from the v1
// specification; Status is its HTTP equivalent for a future T6 layer.
type NativeCampaignError struct {
	Code         string         `json:"code"`
	Status       int            `json:"-"`
	Message      string         `json:"message"`
	State        string         `json:"state,omitempty"`
	StateVersion int64          `json:"state_version,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

func (e *NativeCampaignError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// NativeCampaignErrorCode returns the stable code of a NativeCampaignError and
// an empty string for any other error.
func NativeCampaignErrorCode(err error) string {
	var campaignErr *NativeCampaignError
	if errors.As(err, &campaignErr) && campaignErr != nil {
		return campaignErr.Code
	}
	return ""
}

func nativeCampaignErrorf(code string, status int, format string, args ...any) *NativeCampaignError {
	return &NativeCampaignError{Code: code, Status: status, Message: fmt.Sprintf(format, args...)}
}

// NativeCampaignAuthorizationRequest is the explicit input handed to an
// authorizer before any durable T3 mutation. Callers must supply an authorizer;
// there is intentionally no nil/default bypass.
type NativeCampaignAuthorizationRequest struct {
	TaskID     int64
	CampaignID int64
	Action     string
	ActorKind  string
	ActorID    int64
}

// NativeCampaignAuthorizer is supplied by the caller (T4 service layer in
// production, an explicit test callback in unit tests). Returning a non-nil
// error aborts the mutation before a transaction is opened.
type NativeCampaignAuthorizer func(context.Context, NativeCampaignAuthorizationRequest) error

// NativeCampaignCommandResponse is the stored/returned snapshot of a mutation
// command. Body is the canonical JSON object kept in
// native_campaign_requests.response_body so a replay returns exactly the stored
// response.
type NativeCampaignCommandResponse struct {
	Status           int
	Body             json.RawMessage
	Replayed         bool
	AlreadyQueued    bool
	AlreadyPaused    bool
	AlreadyFinalized bool
}

func (r *NativeCampaignCommandResponse) Decode(v any) error {
	if r == nil || len(r.Body) == 0 {
		return errors.New("empty native campaign response")
	}
	return json.Unmarshal(r.Body, v)
}
