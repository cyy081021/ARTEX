package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"
)

// Native Campaign v1 (T3) pure state machine, claim/fencing and finalize
// transactions. This file intentionally has no scheduler, runner, HTTP or
// filesystem/container side effect. Every mutation requires an explicit
// NativeCampaignAuthorizer and every durable state transition is either CAS'ed
// on state_version or fenced on (attempt id, fencing token, lease owner,
// lease instance, current attempt state).

var nativeCampaignActiveAttemptStates = map[string]struct{}{
	"claimed": {}, "launching": {}, "running": {}, "stopping": {}, "collecting": {}, "cleaning": {},
}

var nativeCampaignTerminalAttemptStates = map[string]struct{}{
	"paused": {}, "completed": {}, "failed": {}, "cancelled": {}, "interrupted": {},
}

var nativeCampaignTerminalCampaignStates = map[string]struct{}{
	"completed": {}, "failed": {}, "cancelled": {},
}

var nativeCampaignValidPhases = map[string]struct{}{
	"preflight": {}, "startup": {}, "tool_probe": {}, "instrumentation_probe": {},
	"campaign": {}, "pause_collect": {}, "checkpoint_write": {}, "cleanup": {},
	"evidence": {}, "finalize": {},
}

// NativeCampaignCreateCommand creates a draft, its idempotency row and its
// campaign.created event in one transaction. It never starts a runner.
type NativeCampaignCreateCommand struct {
	TaskID         int64
	RequestID      string
	ArtifactID     int64
	ProfileID      string
	CreatorKind    string
	CreatorID      int64
	Spec           json.RawMessage
	ArtifactSHA256 string
	ImageDigest    string
	ImageID        string
	PolicyRevision int64
	ConfigRevision int64
	TotalBudgetMS  int64
	ActorKind      string
	ActorID        int64
}

// NativeCampaignStateCommand is shared by start/pause/cancel/resume.
type NativeCampaignStateCommand struct {
	TaskID               int64
	CampaignID           int64
	RequestID            string
	ExpectedStateVersion int64
	AttemptBudgetMS      *int64
	Reason               string
	ActorKind            string
	ActorID              int64
}

// NativeCampaignClaimCommand is the internal scheduler claim input. It is not a
// client action and therefore has no request_id.
type NativeCampaignClaimCommand struct {
	TaskID          int64
	CampaignID      int64
	LeaseInstance   string
	LeaseMS         int64
	AttemptBudgetMS *int64
	// DefaultAttemptBudgetMS is retained for source compatibility only. It is
	// ignored: the persisted immutable spec (or the fixed legacy compatibility
	// default) is the sole source of an omitted claim budget, and a caller
	// default must never override it.
	DefaultAttemptBudgetMS int64
	ProfileMaxDurationMS   int64
	PolicyMaxDurationMS    int64
	OperatorKind           string
	OperatorID             int64
	ImageID                string
	ActorKind              string
	ActorID                int64
}

type NativeCampaignClaimResult struct {
	Attempt        *NativeCampaignAttempt   `json:"attempt"`
	Plan           NativeCampaignBudgetPlan `json:"budget"`
	LeaseExpiresAt time.Time                `json:"lease_expires_at"`
}

// NativeCampaignFinalizeCommand is the fenced final write for one attempt.
type NativeCampaignFinalizeCommand struct {
	// Internal successful-Wait handoff. Neither field authorizes cleanup alone.
	CreationSeal           json.RawMessage
	ExpectedOwnedResources json.RawMessage
	TaskID                 int64
	CampaignID             int64
	AttemptID              int64
	FencingToken           int64
	LeaseOwner             string
	LeaseInstance          string
	TargetState            string
	Phase                  string
	CleanupStatus          string
	CheckpointID           *int64
	EvidenceID             int64
	// Internal file-first handoff; exactly one of EvidenceInput/EvidenceID.
	EvidenceInput     *NativeCampaignEvidenceInput
	TerminationReason string
	ErrorCode         string
	ErrorMessage      string
	ActualElapsedMS   int64
	CleanupElapsedMS  int64
	CleanupReserveMS  int64
	FinalLost         bool
	BudgetOverrun     bool
	ActorKind         string
	ActorID           int64
}

type NativeCampaignFinalizeResult struct {
	Campaign         *NativeCampaign          `json:"campaign"`
	Attempt          *NativeCampaignAttempt   `json:"attempt"`
	Settlement       NativeCampaignSettlement `json:"settlement"`
	AlreadyFinalized bool                     `json:"already_finalized"`
}

// NativeCampaignCleanupCommand retries only cleanup for a failed/interrupted
// attempt. It cannot re-run or resume the campaign.
type NativeCampaignCleanupCommand struct {
	TaskID           int64
	CampaignID       int64
	AttemptID        int64
	CleanupVerified  bool
	CleanupElapsedMS int64
	ActorKind        string
	ActorID          int64
}

type NativeCampaignCleanupResult struct {
	Campaign *NativeCampaign        `json:"campaign"`
	Attempt  *NativeCampaignAttempt `json:"attempt"`
}

type NativeCampaignValidationCheck struct {
	OK          bool   `json:"ok"`
	Code        string `json:"code,omitempty"`
	RemainingMS int64  `json:"remaining_ms,omitempty"`
}

type NativeCampaignValidation struct {
	CampaignID int64                                    `json:"campaign_id"`
	SpecHash   string                                   `json:"spec_hash"`
	CanStart   bool                                     `json:"can_start"`
	CanResume  bool                                     `json:"can_resume"`
	Checks     map[string]NativeCampaignValidationCheck `json:"checks"`
	Warnings   []string                                 `json:"warnings"`
}

func nativeCampaignStateConflict(c *NativeCampaign) *NativeCampaignError {
	return &NativeCampaignError{
		Code: "state_conflict", Status: 409, Message: "campaign state or state_version changed",
		State: c.State, StateVersion: c.StateVersion,
	}
}

func nativeCampaignNotFound(what string) *NativeCampaignError {
	return nativeCampaignErrorf("not_found", 404, "%s does not belong to the task", what)
}

func nativeCampaignTerminalError(c *NativeCampaign) *NativeCampaignError {
	return &NativeCampaignError{
		Code: "terminal_campaign", Status: 409, Message: "campaign is terminal",
		State: c.State, StateVersion: c.StateVersion,
	}
}

func loadNativeCampaignTx(ctx context.Context, tx *sql.Tx, taskID, campaignID int64, skipLocked bool) (*NativeCampaign, error) {
	lock := "FOR UPDATE"
	if skipLocked {
		lock += " SKIP LOCKED"
	}
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT row_to_json(c) FROM (
		SELECT * FROM native_campaigns WHERE task_id=$1 AND id=$2 `+lock+`) c`,
		taskID, campaignID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaign
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func loadNativeCampaignAttemptTx(ctx context.Context, tx *sql.Tx, taskID, campaignID, attemptID int64) (*NativeCampaignAttempt, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT row_to_json(a) FROM (
		SELECT * FROM native_campaign_attempts
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3 FOR UPDATE) a`,
		taskID, campaignID, attemptID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var out NativeCampaignAttempt
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func insertNativeCampaignEventTx(ctx context.Context, tx *sql.Tx, in NativeCampaignEventInput) error {
	if in.Kind == nativeCampaignArchiveRestoredEvent {
		return nativeCampaignErrorf("invalid_request", 400, "reserved archive event")
	}
	if in.TaskID <= 0 || in.CampaignID <= 0 {
		return nativeCampaignErrorf("internal", 500, "event task/campaign id is missing")
	}
	if len(in.Kind) < 1 || len(in.Kind) > 64 {
		return nativeCampaignErrorf("internal", 500, "event kind must be 1..64 characters")
	}
	payload, err := normalizeNativeCampaignJSONObject(in.Payload, 16384, "payload")
	if err != nil {
		return nativeCampaignErrorf("internal", 500, "event payload: %v", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO native_campaign_events(
		task_id,campaign_id,attempt_id,kind,payload) VALUES($1,$2,$3,$4,$5)`,
		in.TaskID, in.CampaignID, in.AttemptID, in.Kind, payload)
	return err
}

func nativeCampaignValidateReason(reason string) error {
	if utf8.RuneCountInString(reason) > 512 {
		return nativeCampaignErrorf("invalid_request", 400, "reason exceeds 512 characters")
	}
	if strings.ContainsRune(reason, 0) {
		return nativeCampaignErrorf("invalid_request", 400, "reason contains NUL")
	}
	return nil
}

func nativeCampaignValidateAttemptBudget(budget *int64, remaining int64) error {
	if budget == nil {
		return nil
	}
	if *budget < NativeCampaignMinAttemptBudgetMS {
		return nativeCampaignErrorf("invalid_request", 400,
			"attempt_budget_ms %d is below the %dms minimum", *budget, NativeCampaignMinAttemptBudgetMS)
	}
	if *budget > NativeCampaignMaxAttemptBudgetMS {
		return nativeCampaignErrorf("invalid_request", 400,
			"attempt_budget_ms %d exceeds the %dms attempt maximum", *budget, NativeCampaignMaxAttemptBudgetMS)
	}
	if *budget > remaining {
		return nativeCampaignErrorf("budget_exhausted", 409,
			"attempt_budget_ms %d exceeds remaining budget %dms", *budget, remaining)
	}
	return nil
}

func (d *DB) campaignCreatePayload(cmd NativeCampaignCreateCommand, specCanonical []byte) map[string]any {
	// Every persisted effect field is part of the request identity. Creator is
	// audit identity (not execution identity) but changing it must still be a
	// different request, never a replay. Authorization is re-verified on every
	// replay before the idempotency row is read.
	return map[string]any{
		"artifact_id":     cmd.ArtifactID,
		"profile_id":      cmd.ProfileID,
		"total_budget_ms": cmd.TotalBudgetMS,
		"artifact_sha256": cmd.ArtifactSHA256,
		"image_digest":    cmd.ImageDigest,
		"image_id":        cmd.ImageID,
		"policy_revision": cmd.PolicyRevision,
		"config_revision": cmd.ConfigRevision,
		"creator_kind":    cmd.CreatorKind,
		"creator_id":      cmd.CreatorID,
		"spec_hash_bytes": string(specCanonical),
	}
}

// bindNativeCampaignSpec makes the immutable spec contain the full execution
// identity and authorized budget. If the caller's spec already carries a
// conflicting projection, the create is rejected instead of silently sharing a
// spec_hash across different artifact/profile/image/policy/config/budget.
func bindNativeCampaignSpec(cmd NativeCampaignCreateCommand) ([]byte, string, error) {
	canonical, _, err := CanonicalNativeCampaignSpec(cmd.Spec)
	if err != nil {
		return nil, "", err
	}
	dec := json.NewDecoder(strings.NewReader(string(canonical)))
	dec.UseNumber()
	var spec map[string]any
	if err := dec.Decode(&spec); err != nil {
		return nil, "", nativeCampaignErrorf("invalid_request", 400, "spec must be a JSON object: %v", err)
	}
	bindings := map[string]any{
		"artifact_sha256": cmd.ArtifactSHA256,
		"profile_id":      cmd.ProfileID,
		"image_digest":    cmd.ImageDigest,
		"image_id":        cmd.ImageID,
		"policy_revision": cmd.PolicyRevision,
		"config_revision": cmd.ConfigRevision,
		"total_budget_ms": cmd.TotalBudgetMS,
	}
	for key, want := range bindings {
		if existing, ok := spec[key]; ok {
			existingJSON, err := canonicalNativeCampaignJSON(existing)
			if err != nil {
				return nil, "", err
			}
			wantJSON, err := canonicalNativeCampaignJSON(want)
			if err != nil {
				return nil, "", err
			}
			if string(existingJSON) != string(wantJSON) {
				return nil, "", nativeCampaignErrorf("invalid_request", 400,
					"spec field %s conflicts with the persisted campaign projection", key)
			}
		}
		spec[key] = want
	}
	bound, err := json.Marshal(spec)
	if err != nil {
		return nil, "", nativeCampaignErrorf("invalid_request", 400, "bind spec: %v", err)
	}
	normalized, err := normalizeNativeCampaignJSONObject(bound, NativeCampaignSpecBytes, "spec")
	if err != nil {
		return nil, "", nativeCampaignErrorf("invalid_request", 400, "%v", err)
	}
	sum := sha256.Sum256(normalized)
	return normalized, hex.EncodeToString(sum[:]), nil
}

// CreateNativeCampaignDraft creates only a draft plus its idempotency response.
func (d *DB) CreateNativeCampaignDraft(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignCreateCommand) (*NativeCampaignCommandResponse, error) {
	if cmd.TaskID <= 0 || cmd.ArtifactID <= 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "task_id and artifact_id are required")
	}
	if cmd.CreatorKind == "" {
		cmd.CreatorKind = "admin"
	}
	if (cmd.CreatorKind == "admin" && cmd.CreatorID != 0) ||
		(cmd.CreatorKind == "intent" && cmd.CreatorID <= 0) ||
		(cmd.CreatorKind != "admin" && cmd.CreatorKind != "intent") {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid creator_kind/creator_id")
	}
	cmd.ProfileID = strings.TrimSpace(cmd.ProfileID)
	if len(cmd.ProfileID) < 1 || len(cmd.ProfileID) > 64 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "profile_id must be 1..64 characters")
	}
	cmd.ImageDigest = strings.TrimSpace(cmd.ImageDigest)
	if len(cmd.ImageDigest) < 1 || len(cmd.ImageDigest) > 512 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "image_digest must be 1..512 characters")
	}
	if cmd.PolicyRevision < 1 || cmd.ConfigRevision < 1 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "policy_revision and config_revision must be >= 1")
	}
	if cmd.TotalBudgetMS < NativeCampaignMinAttemptBudgetMS || cmd.TotalBudgetMS > NativeCampaignMaxTotalBudgetMS {
		return nil, nativeCampaignErrorf("invalid_request", 400,
			"total_budget_ms must be between %d and %d", NativeCampaignMinAttemptBudgetMS, NativeCampaignMaxTotalBudgetMS)
	}
	if err := validateNativeCampaignSHA256(cmd.ArtifactSHA256, "artifact_sha256"); err != nil {
		return nil, nativeCampaignErrorf("invalid_request", 400, "%v", err)
	}
	if cmd.ImageID != "" {
		if len(cmd.ImageID) != len("sha256:")+64 || !strings.HasPrefix(cmd.ImageID, "sha256:") ||
			!nativeCampaignSHA256Pattern(cmd.ImageID[len("sha256:"):]) {
			return nil, nativeCampaignErrorf("invalid_request", 400, "image_id must be empty or sha256:<64 lowercase hex>")
		}
	}
	specCanonical, specHash, err := bindNativeCampaignSpec(cmd)
	if err != nil {
		return nil, err
	}
	payload := d.campaignCreatePayload(cmd, specCanonical)
	authReq := NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, Action: "create", ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}
	return d.executeNativeCampaignMutation(ctx, auth, authReq, "create", cmd.RequestID, payload,
		func(ctx context.Context, tx *sql.Tx) (int, any, nativeCampaignRequestFlags, error) {
			var explorationID int64
			if err := tx.QueryRowContext(ctx,
				`SELECT exploration_id FROM tasks WHERE id=$1 AND kind='reverse' AND deleted_at IS NULL`,
				cmd.TaskID).Scan(&explorationID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("task")
				}
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			var artifactSHA string
			if err := tx.QueryRowContext(ctx,
				`SELECT sha256 FROM reverse_artifacts WHERE id=$1 AND task_id=$2`,
				cmd.ArtifactID, cmd.TaskID).Scan(&artifactSHA); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("artifact")
				}
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			if artifactSHA != cmd.ArtifactSHA256 {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignErrorf(
					"invalid_request", 400, "artifact_sha256 does not match the task artifact")
			}
			var imageID any
			if cmd.ImageID != "" {
				imageID = cmd.ImageID
			}
			var raw []byte
			if err := tx.QueryRowContext(ctx, `WITH c AS (
				INSERT INTO native_campaigns(
					task_id,artifact_id,creator_kind,creator_id,spec,spec_hash,artifact_sha256,
					profile_id,image_digest,image_id,policy_revision,config_revision,total_budget_ms)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
				RETURNING *) SELECT row_to_json(c) FROM c`,
				cmd.TaskID, cmd.ArtifactID, cmd.CreatorKind, cmd.CreatorID, specCanonical, specHash,
				cmd.ArtifactSHA256, cmd.ProfileID, cmd.ImageDigest, imageID,
				cmd.PolicyRevision, cmd.ConfigRevision, cmd.TotalBudgetMS).Scan(&raw); err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			var campaign NativeCampaign
			if err := json.Unmarshal(raw, &campaign); err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			eventPayload, _ := json.Marshal(map[string]any{
				"spec_hash": specHash, "artifact_sha256": cmd.ArtifactSHA256,
			})
			if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
				TaskID: cmd.TaskID, CampaignID: campaign.ID, Kind: "campaign.created",
				Payload: eventPayload,
			}); err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			return 201, map[string]any{"campaign": campaign, "replayed": false}, nativeCampaignRequestFlags{}, nil
		})
}

// StartNativeCampaign implements the draft/queued start edges.
func (d *DB) StartNativeCampaign(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignStateCommand) (*NativeCampaignCommandResponse, error) {
	if err := d.validateNativeCampaignStateCommand(cmd); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"campaign_id":            cmd.CampaignID,
		"expected_state_version": cmd.ExpectedStateVersion,
	}
	if cmd.AttemptBudgetMS != nil {
		payload["attempt_budget_ms"] = *cmd.AttemptBudgetMS
	}
	authReq := NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "start",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}
	return d.executeNativeCampaignMutation(ctx, auth, authReq, "start", cmd.RequestID, payload,
		func(ctx context.Context, tx *sql.Tx) (int, any, nativeCampaignRequestFlags, error) {
			campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("campaign")
			}
			if err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			if campaign.StateVersion != cmd.ExpectedStateVersion {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			}
			if err := nativeCampaignValidateAttemptBudget(cmd.AttemptBudgetMS, campaign.TotalBudgetMS-campaign.ChargedBudgetMS); err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			switch campaign.State {
			case "draft":
				remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
				if remaining < NativeCampaignMinAttemptBudgetMS {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignErrorf(
						"budget_exhausted", 409, "remaining budget is below the 6000ms minimum")
				}
				if cmd.AttemptBudgetMS == nil {
					if err := nativeCampaignValidateDefaultAttemptBudget(campaign.Spec, remaining); err != nil {
						return 0, nil, nativeCampaignRequestFlags{}, err
					}
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='queued', desired_state='running',
						state_version=state_version+1, pause_origin='none', ended_at=NULL,
						termination_reason=NULL, last_error_code=NULL, last_error_message=NULL
					WHERE task_id=$1 AND id=$2 AND state='draft' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"attempt_budget_ms": nativeCampaignPointerValue(cmd.AttemptBudgetMS)})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.queued", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponseWithBudget(updated, false, false, cmd.AttemptBudgetMS), nativeCampaignRequestFlags{}, nil
			case "queued":
				if campaign.DesiredState == "running" {
					return 200, nativeCampaignStateResponse(*campaign, true, false), nativeCampaignRequestFlags{alreadyQueued: true}, nil
				}
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			case "paused", "interrupted":
				return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
					Code: "resume_required", Status: 409, Message: "campaign must be resumed, not started",
					State: campaign.State, StateVersion: campaign.StateVersion,
				}
			case "running", "stopping":
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			default:
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignTerminalError(campaign)
			}
		})
}

// PauseNativeCampaign implements queued empty/reuse pause and the running pause
// request. It never collects a checkpoint itself; T5 does the actual collection.
func (d *DB) PauseNativeCampaign(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignStateCommand) (*NativeCampaignCommandResponse, error) {
	if err := d.validateNativeCampaignStateCommand(cmd); err != nil {
		return nil, err
	}
	if err := nativeCampaignValidateReason(cmd.Reason); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"campaign_id": cmd.CampaignID, "expected_state_version": cmd.ExpectedStateVersion,
		"reason": cmd.Reason,
	}
	authReq := NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "pause",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}
	return d.executeNativeCampaignMutation(ctx, auth, authReq, "pause", cmd.RequestID, payload,
		func(ctx context.Context, tx *sql.Tx) (int, any, nativeCampaignRequestFlags, error) {
			campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("campaign")
			}
			if err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			if campaign.StateVersion != cmd.ExpectedStateVersion {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			}
			switch campaign.State {
			case "draft":
				return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
					Code: "not_started", Status: 409, Message: "campaign has not been started",
					State: campaign.State, StateVersion: campaign.StateVersion,
				}
			case "queued":
				if campaign.CurrentAttemptID != nil && campaign.LatestCheckpointID == nil {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "no_checkpoint", Status: 409, Message: "queued campaign has an attempt but no verified checkpoint",
						State: campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				cleanup := "not_required"
				eventKind := "campaign.paused_empty"
				if campaign.CurrentAttemptID != nil || campaign.LatestCheckpointID != nil {
					if campaign.CurrentAttemptID == nil || campaign.LatestCheckpointID == nil {
						return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
					}
					var checkpointState string
					if err := tx.QueryRowContext(ctx, `SELECT state FROM native_campaign_checkpoints
						WHERE id=$1 AND campaign_id=$2 AND task_id=$3`,
						*campaign.LatestCheckpointID, campaign.ID, campaign.TaskID).Scan(&checkpointState); err != nil {
						return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
					}
					if checkpointState != "verified" {
						return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignErrorf(
							"resume_blocked", 409, "latest checkpoint is not verified")
					}
					cleanup = "verified"
					eventKind = "campaign.paused_reuse_checkpoint"
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='paused', desired_state='paused',
						pause_origin='queued', cleanup_status=$4, state_version=state_version+1,
						ended_at=now(), termination_reason=NULL, last_error_code=NULL, last_error_message=NULL
					WHERE task_id=$1 AND id=$2 AND state='queued' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion, cleanup).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{
					"pause_origin": "queued", "checkpoint_id": nativeCampaignPointerValue(updated.LatestCheckpointID),
				})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: eventKind, Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 200, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "running":
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='stopping', desired_state='paused',
						pause_origin='running', state_version=state_version+1
					WHERE task_id=$1 AND id=$2 AND state='running' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "pause.requested", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "stopping":
				if campaign.DesiredState == "cancelled" {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "cancel_in_progress", Status: 409, Message: "cancel already owns the stop",
						State: campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				return 202, nativeCampaignStateResponse(*campaign, false, true), nativeCampaignRequestFlags{alreadyPaused: true}, nil
			case "paused":
				if campaign.DesiredState == "paused" {
					return 200, nativeCampaignStateResponse(*campaign, false, true), nativeCampaignRequestFlags{alreadyPaused: true}, nil
				}
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			default:
				if _, terminal := nativeCampaignTerminalCampaignStates[campaign.State]; terminal {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignTerminalError(campaign)
				}
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			}
		})
}

// CancelNativeCampaign implements cancel and pause-to-cancel upgrade edges.
func (d *DB) CancelNativeCampaign(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignStateCommand) (*NativeCampaignCommandResponse, error) {
	if err := d.validateNativeCampaignStateCommand(cmd); err != nil {
		return nil, err
	}
	if err := nativeCampaignValidateReason(cmd.Reason); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"campaign_id": cmd.CampaignID, "expected_state_version": cmd.ExpectedStateVersion,
		"reason": cmd.Reason,
	}
	authReq := NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "cancel",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}
	return d.executeNativeCampaignMutation(ctx, auth, authReq, "cancel", cmd.RequestID, payload,
		func(ctx context.Context, tx *sql.Tx) (int, any, nativeCampaignRequestFlags, error) {
			campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("campaign")
			}
			if err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			if campaign.StateVersion != cmd.ExpectedStateVersion {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			}
			switch campaign.State {
			case "draft", "queued":
				// queued cancel never creates an attempt or new cleanup and must
				// preserve a prior verified checkpoint/charge. A queued campaign
				// without a checkpoint may still retain the last attempt (for
				// example after an interrupted resume), so checkpoint presence is
				// not required here.
				cleanup := "not_required"
				if campaign.CurrentAttemptID != nil || campaign.LatestCheckpointID != nil {
					if campaign.CleanupStatus != "verified" {
						return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
					}
					cleanup = "verified"
				} else if campaign.CleanupStatus == "verified" {
					cleanup = "verified"
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='cancelled', desired_state='cancelled',
						cleanup_status=$4, pause_origin='none', state_version=state_version+1,
						ended_at=now(), termination_reason='cancelled'
					WHERE task_id=$1 AND id=$2 AND state=$3 AND state_version=$5
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, campaign.State, cleanup, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.cancelled", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 200, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "running":
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='stopping', desired_state='cancelled',
						pause_origin='none', state_version=state_version+1
					WHERE task_id=$1 AND id=$2 AND state='running' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "cancel.requested", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "stopping":
				if campaign.DesiredState == "cancelled" {
					return 202, nativeCampaignStateResponse(*campaign, false, false), nativeCampaignRequestFlags{}, nil
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET desired_state='cancelled', state_version=state_version+1
					WHERE task_id=$1 AND id=$2 AND state='stopping' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "cancel.upgraded", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "paused":
				if campaign.CleanupStatus != "verified" && campaign.CleanupStatus != "not_required" {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='cancelled', desired_state='cancelled',
						cleanup_status=$4, pause_origin='none', state_version=state_version+1,
						ended_at=now(), termination_reason='cancelled'
					WHERE task_id=$1 AND id=$2 AND state='paused' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion, campaign.CleanupStatus).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.cancelled", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 200, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			case "interrupted":
				if campaign.CleanupStatus != "verified" {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "cleanup_unknown", Status: 503,
						Message: "interrupted campaign cleanup is not verified; run a cleanup probe first",
						State:   campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				var raw []byte
				err := tx.QueryRowContext(ctx, `WITH c AS (
					UPDATE native_campaigns SET state='cancelled', desired_state='cancelled',
						cleanup_status='verified', pause_origin='none', state_version=state_version+1,
						ended_at=now(), termination_reason='cancelled'
					WHERE task_id=$1 AND id=$2 AND state='interrupted' AND state_version=$3
					RETURNING *) SELECT row_to_json(c) FROM c`,
					cmd.TaskID, cmd.CampaignID, cmd.ExpectedStateVersion).Scan(&raw)
				if errors.Is(err, sql.ErrNoRows) {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
				}
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				var updated NativeCampaign
				if err := json.Unmarshal(raw, &updated); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{"reason": cmd.Reason})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.cancelled", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 200, nativeCampaignStateResponse(updated, false, false), nativeCampaignRequestFlags{}, nil
			default:
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignTerminalError(campaign)
			}
		})
}

// ResumeNativeCampaign implements paused/interrupted -> queued. It never creates
// an attempt, never refreshes total_budget_ms and never clears checkpoints.
func (d *DB) ResumeNativeCampaign(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignStateCommand) (*NativeCampaignCommandResponse, error) {
	if err := d.validateNativeCampaignStateCommand(cmd); err != nil {
		return nil, err
	}
	payload := map[string]any{
		"campaign_id": cmd.CampaignID, "expected_state_version": cmd.ExpectedStateVersion,
	}
	if cmd.AttemptBudgetMS != nil {
		payload["attempt_budget_ms"] = *cmd.AttemptBudgetMS
	}
	authReq := NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "resume",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}
	return d.executeNativeCampaignMutation(ctx, auth, authReq, "resume", cmd.RequestID, payload,
		func(ctx context.Context, tx *sql.Tx) (int, any, nativeCampaignRequestFlags, error) {
			campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
			if errors.Is(err, sql.ErrNoRows) {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignNotFound("campaign")
			}
			if err != nil {
				return 0, nil, nativeCampaignRequestFlags{}, err
			}
			if campaign.StateVersion != cmd.ExpectedStateVersion {
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			}
			switch campaign.State {
			case "paused":
				emptyPause := campaign.CurrentAttemptID == nil && campaign.LatestCheckpointID == nil &&
					campaign.CleanupStatus == "not_required" && campaign.PauseOrigin == "queued"
				if !emptyPause && campaign.CleanupStatus != "verified" {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "cleanup_unknown", Status: 503,
						Message: "paused campaign cleanup is not verified",
						State:   campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				if !emptyPause && campaign.LatestCheckpointID == nil {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "resume_blocked", Status: 409, Message: "paused campaign has no verified checkpoint",
						State: campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
				if remaining < NativeCampaignMinAttemptBudgetMS {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignErrorf(
						"budget_exhausted", 409, "remaining budget is below the 6000ms minimum")
				}
				if err := nativeCampaignValidateAttemptBudget(cmd.AttemptBudgetMS, remaining); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				if cmd.AttemptBudgetMS == nil {
					if err := nativeCampaignValidateDefaultAttemptBudget(campaign.Spec, remaining); err != nil {
						return 0, nil, nativeCampaignRequestFlags{}, err
					}
				}
				var count int
				if err := tx.QueryRowContext(ctx,
					`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2`,
					campaign.TaskID, campaign.ID).Scan(&count); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				if count >= 1000 {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "attempt_limit", Status: 409, Message: "campaign reached the 1000 attempt limit",
						State: campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				resumeSource := "checkpoint"
				if emptyPause {
					resumeSource = "initial_spec"
				}
				updated, err := resumeCampaignTx(ctx, tx, campaign, cmd.ExpectedStateVersion)
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{
					"resume_source": resumeSource, "checkpoint_id": nativeCampaignPointerValue(updated.LatestCheckpointID),
					"attempt_budget_ms": nativeCampaignPointerValue(cmd.AttemptBudgetMS),
				})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.resume_queued", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponseWithBudget(*updated, false, false, cmd.AttemptBudgetMS), nativeCampaignRequestFlags{}, nil
			case "interrupted":
				if campaign.CleanupStatus != "verified" {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "cleanup_unknown", Status: 503,
						Message: "interrupted campaign cleanup is not verified",
						State:   campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
				if remaining < NativeCampaignMinAttemptBudgetMS {
					return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignErrorf(
						"budget_exhausted", 409, "remaining budget is below the 6000ms minimum")
				}
				if err := nativeCampaignValidateAttemptBudget(cmd.AttemptBudgetMS, remaining); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				if cmd.AttemptBudgetMS == nil {
					if err := nativeCampaignValidateDefaultAttemptBudget(campaign.Spec, remaining); err != nil {
						return 0, nil, nativeCampaignRequestFlags{}, err
					}
				}
				var count int
				if err := tx.QueryRowContext(ctx,
					`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2`,
					campaign.TaskID, campaign.ID).Scan(&count); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				if count >= 1000 {
					return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
						Code: "attempt_limit", Status: 409, Message: "campaign reached the 1000 attempt limit",
						State: campaign.State, StateVersion: campaign.StateVersion,
					}
				}
				resumeSource := "checkpoint"
				lostProgress := false
				if campaign.LatestCheckpointID == nil {
					resumeSource = "initial_spec"
					lostProgress = true
				}
				updated, err := resumeCampaignTx(ctx, tx, campaign, cmd.ExpectedStateVersion)
				if err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				eventPayload, _ := json.Marshal(map[string]any{
					"resume_source": resumeSource, "checkpoint_id": nativeCampaignPointerValue(updated.LatestCheckpointID),
					"lost_progress": lostProgress, "attempt_budget_ms": nativeCampaignPointerValue(cmd.AttemptBudgetMS),
				})
				if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
					TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Kind: "campaign.resume_queued", Payload: eventPayload,
				}); err != nil {
					return 0, nil, nativeCampaignRequestFlags{}, err
				}
				return 202, nativeCampaignStateResponseWithBudget(*updated, false, false, cmd.AttemptBudgetMS), nativeCampaignRequestFlags{}, nil
			case "draft":
				return 0, nil, nativeCampaignRequestFlags{}, &NativeCampaignError{
					Code: "not_started", Status: 409, Message: "campaign has not been started",
					State: campaign.State, StateVersion: campaign.StateVersion,
				}
			case "queued", "running", "stopping":
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignStateConflict(campaign)
			default:
				return 0, nil, nativeCampaignRequestFlags{}, nativeCampaignTerminalError(campaign)
			}
		})
}

func resumeCampaignTx(ctx context.Context, tx *sql.Tx, campaign *NativeCampaign, expectedVersion int64) (*NativeCampaign, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `WITH c AS (
		UPDATE native_campaigns SET state='queued', desired_state='running',
			pause_origin='none', state_version=state_version+1, ended_at=NULL,
			termination_reason=NULL, last_error_code=NULL, last_error_message=NULL
		WHERE task_id=$1 AND id=$2 AND state=$3 AND state_version=$4
		RETURNING *) SELECT row_to_json(c) FROM c`,
		campaign.TaskID, campaign.ID, campaign.State, expectedVersion).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignStateConflict(campaign)
	}
	if err != nil {
		return nil, err
	}
	var updated NativeCampaign
	if err := json.Unmarshal(raw, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func nativeCampaignStateResponse(campaign NativeCampaign, alreadyQueued, alreadyPaused bool) map[string]any {
	body := map[string]any{
		"campaign_id": campaign.ID, "state": campaign.State,
		"desired_state": campaign.DesiredState, "state_version": campaign.StateVersion,
		"cleanup_status": campaign.CleanupStatus, "pause_origin": campaign.PauseOrigin,
		"charged_budget_ms": campaign.ChargedBudgetMS, "total_budget_ms": campaign.TotalBudgetMS,
		"current_attempt_id":   campaign.CurrentAttemptID,
		"latest_checkpoint_id": campaign.LatestCheckpointID,
		"replayed":             false,
	}
	if alreadyQueued {
		body["already_queued"] = true
	}
	if alreadyPaused {
		body["already_paused"] = true
	}
	return body
}

func nativeCampaignStateResponseWithBudget(campaign NativeCampaign, alreadyQueued, alreadyPaused bool, budget *int64) map[string]any {
	body := nativeCampaignStateResponse(campaign, alreadyQueued, alreadyPaused)
	body["attempt_budget_ms"] = nativeCampaignPointerValue(budget)
	return body
}

func nativeCampaignPointerValue(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func (d *DB) validateNativeCampaignStateCommand(cmd NativeCampaignStateCommand) error {
	if cmd.TaskID <= 0 || cmd.CampaignID <= 0 {
		return nativeCampaignErrorf("invalid_request", 400, "task_id and campaign_id are required")
	}
	if !validNativeCampaignRequestID(cmd.RequestID) {
		return nativeCampaignErrorf("invalid_request", 400, "request_id must be 1..128 visible ASCII characters")
	}
	if cmd.ExpectedStateVersion < 1 {
		return nativeCampaignErrorf("invalid_request", 400, "expected_state_version must be >= 1")
	}
	return nil
}

// ValidateNativeCampaign is a pure read: it never writes request/event/state rows.
func (d *DB) ValidateNativeCampaign(ctx context.Context, taskID, campaignID int64) (*NativeCampaignValidation, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "task_id and campaign_id are required")
	}
	campaign, err := d.NativeCampaign(ctx, taskID, campaignID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignNotFound("campaign")
	}
	if err != nil {
		return nil, err
	}
	remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
	canStart := (campaign.State == "draft" || campaign.State == "queued") && remaining >= NativeCampaignMinAttemptBudgetMS
	if campaign.State == "queued" && campaign.DesiredState != "running" {
		canStart = false
	}
	var attempts int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2`,
		taskID, campaignID).Scan(&attempts); err != nil {
		return nil, err
	}
	cleanupOK := campaign.CleanupStatus == "verified" || campaign.CleanupStatus == "not_required"
	checkpointOK := campaign.LatestCheckpointID != nil ||
		(campaign.State == "paused" && campaign.PauseOrigin == "queued" &&
			campaign.CurrentAttemptID == nil && campaign.CleanupStatus == "not_required")
	canResume := (campaign.State == "paused" || campaign.State == "interrupted") &&
		cleanupOK && checkpointOK && remaining >= NativeCampaignMinAttemptBudgetMS && attempts < 1000
	checks := map[string]NativeCampaignValidationCheck{
		"state":      {OK: campaign.State != "completed" && campaign.State != "failed" && campaign.State != "cancelled"},
		"budget":     {OK: remaining >= NativeCampaignMinAttemptBudgetMS, RemainingMS: remaining},
		"cleanup":    {OK: cleanupOK, Code: campaign.CleanupStatus},
		"checkpoint": {OK: checkpointOK},
		"attempts":   {OK: attempts < 1000},
	}
	restored, err := d.NativeCampaignArchiveRestored(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	checks["archive"] = NativeCampaignValidationCheck{OK: !restored}
	if restored {
		canStart = false
		canResume = false
		checks["archive"] = NativeCampaignValidationCheck{OK: false, Code: "archive_restore_not_executable"}
	}
	var warnings []string
	if campaign.ImageID == nil || *campaign.ImageID == "" {
		warnings = append(warnings, "image_id is not recorded until the first attempt")
	}
	return &NativeCampaignValidation{
		CampaignID: campaign.ID, SpecHash: campaign.SpecHash,
		CanStart: canStart, CanResume: canResume, Checks: checks, Warnings: warnings,
	}, nil
}

// ClaimNativeCampaignAttempt atomically reserves the global worker slot, inserts
// the runtime/native run and Attempt, assigns the monotonic attempt_no/fence and
// advances the campaign to running. No runner is started.
func (d *DB) ClaimNativeCampaignAttempt(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignClaimCommand) (*NativeCampaignClaimResult, error) {
	if cmd.TaskID <= 0 || cmd.CampaignID <= 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "task_id and campaign_id are required")
	}
	if len(cmd.LeaseInstance) < 1 || len(cmd.LeaseInstance) > 128 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "lease_instance must be 1..128 characters")
	}
	leaseMS, err := ValidateNativeCampaignLeaseMS(cmd.LeaseMS)
	if err != nil {
		return nil, err
	}
	if cmd.OperatorKind == "" {
		cmd.OperatorKind = "admin"
	}
	if (cmd.OperatorKind == "admin" && cmd.OperatorID != 0) ||
		(cmd.OperatorKind == "intent" && cmd.OperatorID <= 0) ||
		(cmd.OperatorKind != "admin" && cmd.OperatorKind != "intent") {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid operator_kind/operator_id")
	}
	if cmd.ImageID != "" {
		if len(cmd.ImageID) != len("sha256:")+64 || !strings.HasPrefix(cmd.ImageID, "sha256:") ||
			!nativeCampaignSHA256Pattern(cmd.ImageID[len("sha256:"):]) {
			return nil, nativeCampaignErrorf("invalid_request", 400, "image_id must be sha256:<64 lowercase hex>")
		}
	}
	if auth == nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "an explicit campaign authorizer is required")
	}
	if err := auth(ctx, NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "claim",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}); err != nil {
		if NativeCampaignErrorCode(err) == "archive_restore_not_executable" {
			return nil, err
		}
		return nil, &NativeCampaignError{Code: "authorization_revoked", Status: 403, Message: "campaign authorization denied"}
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin claim transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('native-campaign-worker/local-afl-1', 0::bigint))`); err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "lock campaign worker slot: %v", err)
	}
	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, true)
	if errors.Is(err, sql.ErrNoRows) {
		// SKIP LOCKED can hide a row that another claimant currently holds. A
		// non-locking read distinguishes "in progress" from "not found".
		var exists bool
		if scanErr := tx.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM native_campaigns WHERE task_id=$1 AND id=$2)`,
			cmd.TaskID, cmd.CampaignID).Scan(&exists); scanErr != nil {
			return nil, nativeCampaignErrorf("internal", 500, "distinguish locked campaign: %v", scanErr)
		}
		if !exists {
			return nil, nativeCampaignNotFound("campaign")
		}
		return nil, nativeCampaignErrorf("state_conflict", 409, "campaign is being claimed")
	}
	if err != nil {
		return nil, err
	}
	if campaign.State != "queued" || campaign.DesiredState != "running" {
		if _, terminal := nativeCampaignTerminalCampaignStates[campaign.State]; terminal {
			return nil, nativeCampaignTerminalError(campaign)
		}
		return nil, nativeCampaignStateConflict(campaign)
	}
	if campaign.CleanupStatus != "not_required" && campaign.CleanupStatus != "verified" {
		return nil, &NativeCampaignError{
			Code: "cleanup_unknown", Status: 503,
			Message: "campaign cleanup is not verified; refusing a new claim",
			State:   campaign.State, StateVersion: campaign.StateVersion,
		}
	}

	var heldID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM native_campaign_attempts
		WHERE worker_slot=$1 AND resource_hold LIMIT 1`, NativeCampaignWorkerSlot).Scan(&heldID)
	if err == nil {
		return nil, &NativeCampaignError{
			Code: "resource_held", Status: 409,
			Message: "global campaign worker slot is held by an active or unconfirmed attempt",
			Details: map[string]any{"attempt_id": heldID},
		}
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	var maxAttemptNo, attemptCount int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(attempt_no),0), count(*)
		FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2`,
		campaign.TaskID, campaign.ID).Scan(&maxAttemptNo, &attemptCount); err != nil {
		return nil, err
	}
	nextAttemptNo := maxAttemptNo + 1
	if nextAttemptNo > 1000 || attemptCount >= 1000 {
		return nil, &NativeCampaignError{
			Code: "attempt_limit", Status: 409, Message: "campaign reached the 1000 attempt limit",
			State: campaign.State, StateVersion: campaign.StateVersion,
		}
	}
	remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
	// Explicit zero must not silently become "use default". Only a nil pointer
	// may use the durable default; an explicit value must be a real
	// 6000..900000 budget and may only shrink the authorized cap.
	if err := nativeCampaignValidateAttemptBudget(cmd.AttemptBudgetMS, remaining); err != nil {
		return nil, err
	}
	authorizedCap, err := latestNativeCampaignAttemptBudgetCapTx(ctx, tx, campaign.TaskID, campaign.ID)
	if err != nil {
		return nil, err
	}
	var capBudget int64
	if authorizedCap != nil {
		// An explicit start/resume budget cap is the claim authorization. Claim
		// may request a smaller legal budget but may never raise this cap.
		capBudget = *authorizedCap
	} else {
		// No explicit start/resume cap was persisted. The immutable spec's
		// default_attempt_budget_ms (or the legacy 60000ms compatibility
		// default) is the only source of the default authorization. In
		// particular, cmd.DefaultAttemptBudgetMS is not consulted so a
		// scheduler-wide default cannot override the campaign spec.
		capBudget, err = nativeCampaignDefaultAttemptBudgetCapMS(campaign.Spec, remaining)
		if err != nil {
			return nil, err
		}
	}
	requestedBudget := capBudget
	if cmd.AttemptBudgetMS != nil {
		if *cmd.AttemptBudgetMS > capBudget {
			return nil, nativeCampaignErrorf("budget_exhausted", 409,
				"claim budget %d expands the authorized attempt cap %d", *cmd.AttemptBudgetMS, capBudget)
		}
		requestedBudget = *cmd.AttemptBudgetMS
	}
	if requestedBudget > remaining {
		return nil, nativeCampaignErrorf("budget_exhausted", 409,
			"claim budget %d exceeds remaining campaign budget %d", requestedBudget, remaining)
	}
	plan, err := PlanNativeCampaignBudget(NativeCampaignBudgetInput{
		TotalBudgetMS:        campaign.TotalBudgetMS,
		ChargedBudgetMS:      campaign.ChargedBudgetMS,
		RequestedBudgetMS:    requestedBudget,
		ProfileMaxDurationMS: cmd.ProfileMaxDurationMS,
		PolicyMaxDurationMS:  cmd.PolicyMaxDurationMS,
	})
	if err != nil {
		return nil, err
	}

	operatorIntent := int64(0)
	if cmd.OperatorKind == "intent" {
		operatorIntent = cmd.OperatorID
	}
	var runtimeRunID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO reverse_runtime_runs(
		task_id,artifact_id,intent_id,profile_id,status)
		VALUES($1,$2,NULLIF($3,0),$4,'running') RETURNING id`,
		campaign.TaskID, campaign.ArtifactID, operatorIntent, campaign.ProfileID).Scan(&runtimeRunID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO reverse_native_runs(
		run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation)
		VALUES($1,$2,$3,$4,$5,'campaign','running','{}')`,
		runtimeRunID, campaign.TaskID, campaign.ArtifactID, operatorIntent, campaign.ConfigRevision); err != nil {
		return nil, err
	}
	leaseExpires := time.Now().UTC().Add(time.Duration(leaseMS) * time.Millisecond)
	var rawAttempt []byte
	err = tx.QueryRowContext(ctx, `WITH a AS (
		INSERT INTO native_campaign_attempts(
			task_id,campaign_id,attempt_no,native_run_id,runtime_run_id,
			worker_slot,lease_owner,lease_instance,lease_expires_at,
			state,phase,reserved_budget_ms,operator_kind,operator_id,
			cleanup_status,resource_hold,hold_reason)
		VALUES($1,$2,$3,$4,$4,$5,$5,$6,$7,'claimed','preflight',$8,$9,$10,
			'pending',true,'active')
		RETURNING *) SELECT row_to_json(a) FROM a`,
		campaign.TaskID, campaign.ID, nextAttemptNo, runtimeRunID, NativeCampaignWorkerSlot,
		cmd.LeaseInstance, leaseExpires, plan.ReservedBudgetMS, cmd.OperatorKind, cmd.OperatorID).Scan(&rawAttempt)
	if err != nil {
		return nil, mapNativeCampaignClaimSQLError(err)
	}
	var attempt NativeCampaignAttempt
	if err := json.Unmarshal(rawAttempt, &attempt); err != nil {
		return nil, err
	}

	var image any
	if cmd.ImageID != "" {
		image = cmd.ImageID
	}
	var rawCampaign []byte
	err = tx.QueryRowContext(ctx, `WITH c AS (
		UPDATE native_campaigns SET state='running', desired_state='running',
			state_version=state_version+1, current_attempt_id=$3,
			cleanup_status='pending', image_id=COALESCE(image_id,$4),
			started_at=COALESCE(started_at,now()), ended_at=NULL, pause_origin='none',
			termination_reason=NULL, last_error_code=NULL, last_error_message=NULL
		WHERE task_id=$1 AND id=$2 AND state='queued' AND desired_state='running'
		RETURNING *) SELECT row_to_json(c) FROM c`,
		campaign.TaskID, campaign.ID, attempt.ID, image).Scan(&rawCampaign)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignStateConflict(campaign)
	}
	if err != nil {
		return nil, err
	}
	var updated NativeCampaign
	if err := json.Unmarshal(rawCampaign, &updated); err != nil {
		return nil, err
	}
	if campaign.ImageID != nil && *campaign.ImageID != "" && cmd.ImageID != "" && *campaign.ImageID != cmd.ImageID {
		return nil, nativeCampaignErrorf("environment_incompatible", 409, "image_id changed since the previous attempt")
	}
	eventPayload, _ := json.Marshal(map[string]any{
		"attempt_id": attempt.ID, "attempt_no": attempt.AttemptNo,
		"fencing_token": attempt.FencingToken, "reserved_ms": attempt.ReservedBudgetMS,
	})
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: campaign.TaskID, CampaignID: campaign.ID, AttemptID: &attempt.ID,
		Kind: "attempt.claimed", Payload: eventPayload,
	}); err != nil {
		return nil, err
	}
	if err := nativeCampaignFault(ctx, "claim"); err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "injected claim commit failure: %v", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, mapNativeCampaignClaimSQLError(err)
	}
	return &NativeCampaignClaimResult{Attempt: &attempt, Plan: *plan, LeaseExpiresAt: leaseExpires}, nil
}

// latestNativeCampaignAttemptBudgetCapTx reads the most recent operator start or
// resume authorization from the existing append-only event stream. It avoids a
// schema change while giving claim a stable readback of the explicit attempt
// budget cap. A nil cap means the operator omitted the value (default applies).
func latestNativeCampaignAttemptBudgetCapTx(ctx context.Context, tx *sql.Tx, taskID, campaignID int64) (*int64, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT payload FROM native_campaign_events
		WHERE task_id=$1 AND campaign_id=$2
		  AND kind IN ('campaign.queued','campaign.resume_queued')
		ORDER BY id DESC LIMIT 1`, taskID, campaignID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var payload struct {
		AttemptBudgetMS *int64 `json:"attempt_budget_ms"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nativeCampaignErrorf("state_conflict", 409, "queued budget authorization is not readable")
	}
	if payload.AttemptBudgetMS != nil {
		if *payload.AttemptBudgetMS < NativeCampaignMinAttemptBudgetMS ||
			*payload.AttemptBudgetMS > NativeCampaignMaxAttemptBudgetMS {
			return nil, nativeCampaignErrorf("state_conflict", 409, "queued attempt budget cap is outside 6000..900000")
		}
	}
	return payload.AttemptBudgetMS, nil
}

func mapNativeCampaignClaimSQLError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "uq_native_campaign_resource_slot":
			return &NativeCampaignError{Code: "resource_held", Status: 409, Message: "global campaign worker slot is held"}
		case "uq_native_campaign_active_attempt":
			return &NativeCampaignError{Code: "state_conflict", Status: 409, Message: "campaign already has an active attempt"}
		}
	}
	return err
}

// FinalizeNativeCampaignAttempt is the only attempt settlement path. It checks
// the full fence tuple and lease freshness before writing, settles exactly once,
// and commits Attempt state, campaign pointers, evidence/checkpoint references,
// budget charge, runtime/native run status and events in one transaction.
func (d *DB) FinalizeNativeCampaignAttempt(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignFinalizeCommand) (*NativeCampaignFinalizeResult, error) {
	if cmd.TaskID <= 0 || cmd.CampaignID <= 0 || cmd.AttemptID <= 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "task_id, campaign_id and attempt_id are required")
	}
	if cmd.FencingToken <= 0 || cmd.LeaseOwner == "" || cmd.LeaseInstance == "" {
		return nil, nativeCampaignErrorf("invalid_request", 400, "fencing_token, lease_owner and lease_instance are required")
	}
	if _, ok := nativeCampaignTerminalAttemptStates[cmd.TargetState]; !ok {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid target attempt state %q", cmd.TargetState)
	}
	if (cmd.EvidenceID > 0) == (cmd.EvidenceInput != nil) || cmd.EvidenceID < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "exactly one evidence input or evidence_id is required")
	}
	if in := cmd.EvidenceInput; in != nil && (in.TaskID != cmd.TaskID || in.CampaignID != cmd.CampaignID || in.AttemptID != cmd.AttemptID || in.Kind != "attempt_final") {
		return nil, nativeCampaignErrorf("invalid_request", 400, "final evidence identity or kind mismatch")
	}
	if cmd.Phase == "" {
		cmd.Phase = "finalize"
	}
	if _, ok := nativeCampaignValidPhases[cmd.Phase]; !ok {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid attempt phase %q", cmd.Phase)
	}
	if err := nativeCampaignValidateReason(cmd.TerminationReason); err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(cmd.TerminationReason) > 128 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "termination_reason exceeds 128 characters")
	}
	if len(cmd.ErrorCode) > 64 || len(cmd.ErrorMessage) > 512 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "error code/message is too long")
	}
	if auth == nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "an explicit campaign authorizer is required")
	}
	if err := auth(ctx, NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "finalize",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}); err != nil {
		if NativeCampaignErrorCode(err) == "archive_restore_not_executable" {
			return nil, err
		}
		return nil, &NativeCampaignError{Code: "authorization_revoked", Status: 403, Message: "campaign authorization denied"}
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin finalize transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignOwnedSettlement); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignNotFound("campaign")
	}
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, cmd.AttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignNotFound("attempt")
	}
	if err != nil {
		return nil, err
	}
	if attempt.FencingToken != cmd.FencingToken || attempt.LeaseOwner != cmd.LeaseOwner ||
		attempt.LeaseInstance != cmd.LeaseInstance {
		return nil, &NativeCampaignError{Code: "lease_lost", Status: 409, Message: "fencing token or lease identity does not match"}
	}
	if _, terminal := nativeCampaignTerminalAttemptStates[attempt.State]; terminal {
		if attempt.State != cmd.TargetState {
			return nil, &NativeCampaignError{
				Code: "state_conflict", Status: 409, Message: "attempt was already finalized with a different state",
				State: campaign.State, StateVersion: campaign.StateVersion,
				Details: map[string]any{"attempt_state": attempt.State},
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		settlement := NativeCampaignSettlement{
			ReservedBudgetMS: attempt.ReservedBudgetMS, LedgerMS: attempt.ChargedBudgetMS,
			CampaignChargedMS: campaign.ChargedBudgetMS, ActualElapsedMS: attempt.ActualElapsedMS,
			CleanupOverrunMS: attempt.CleanupOverrunMS, BudgetOverrun: attempt.BudgetOverrun,
		}
		return &NativeCampaignFinalizeResult{
			Campaign: campaign, Attempt: attempt, Settlement: settlement, AlreadyFinalized: true,
		}, nil
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, &NativeCampaignError{
			Code: "state_conflict", Status: 409, Message: "attempt is not in an active state",
			State: campaign.State, StateVersion: campaign.StateVersion,
			Details: map[string]any{"attempt_state": attempt.State},
		}
	}
	if !attempt.LeaseExpiresAt.After(time.Now()) {
		return nil, &NativeCampaignError{Code: "lease_lost", Status: 409, Message: "attempt lease has expired"}
	}

	var expectedResources, sealValue any
	if len(cmd.CreationSeal) > 0 {
		if cmd.FinalLost || len(cmd.CreationSeal) > 8192 || len(cmd.ExpectedOwnedResources) == 0 || len(cmd.ExpectedOwnedResources) > 16384 || !json.Valid(cmd.CreationSeal) || !json.Valid(cmd.ExpectedOwnedResources) {
			return nil, nativeCampaignErrorf("invalid_request", 400, "invalid creation seal handoff")
		}
		var seal struct {
			Version      int    `json:"version"`
			TaskID       int64  `json:"task_id"`
			CampaignID   int64  `json:"campaign_id"`
			AttemptID    int64  `json:"attempt_id"`
			FencingToken int64  `json:"fencing_token"`
			PlanSHA256   string `json:"plan_sha256"`
		}
		var resources map[string]json.RawMessage
		if json.Unmarshal(cmd.CreationSeal, &seal) != nil || json.Unmarshal(cmd.ExpectedOwnedResources, &resources) != nil || len(resources["resource_plan"]) == 0 || seal.Version != 1 || seal.TaskID != cmd.TaskID || seal.CampaignID != cmd.CampaignID || seal.AttemptID != cmd.AttemptID || seal.FencingToken != cmd.FencingToken || len(seal.PlanSHA256) != 64 {
			return nil, nativeCampaignErrorf("invalid_request", 400, "creation seal identity/plan mismatch")
		}
		var matches bool
		if err := tx.QueryRowContext(ctx, `SELECT owned_resources=$4::jsonb AND (NOT (owned_resources ? 'creation_seal') OR owned_resources->'creation_seal'=$5::jsonb) FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2 AND id=$3`, cmd.TaskID, cmd.CampaignID, cmd.AttemptID, string(cmd.ExpectedOwnedResources), string(cmd.CreationSeal)).Scan(&matches); err != nil {
			return nil, err
		}
		if !matches {
			return nil, nativeCampaignErrorf("state_conflict", 409, "resource plan changed before creation seal commit")
		}
		expectedResources = string(cmd.ExpectedOwnedResources)
		sealValue = string(cmd.CreationSeal)
	}
	// The Attempt state alone is not enough: a pause final must belong to a
	// pause request, and a cancel final must belong to a cancel request. In
	// particular, a pause that was upgraded to cancel must not let a stale
	// paused final overwrite the cancel.
	lostRaceEvent := ""
	switch cmd.TargetState {
	case "paused":
		if campaign.State != "stopping" || campaign.DesiredState != "paused" {
			return nil, &NativeCampaignError{
				Code: "state_conflict", Status: 409,
				Message: "paused final requires a stopping campaign with desired_state=paused",
				State:   campaign.State, StateVersion: campaign.StateVersion,
			}
		}
	case "cancelled":
		if campaign.State != "stopping" || campaign.DesiredState != "cancelled" {
			return nil, &NativeCampaignError{
				Code: "state_conflict", Status: 409,
				Message: "cancelled final requires a stopping campaign with desired_state=cancelled",
				State:   campaign.State, StateVersion: campaign.StateVersion,
			}
		}
	case "completed":
		switch campaign.State {
		case "running":
		case "stopping":
			switch campaign.DesiredState {
			case "paused":
				lostRaceEvent = "pause_lost_race"
			case "cancelled":
				lostRaceEvent = "cancel_lost_race"
			default:
				return nil, nativeCampaignStateConflict(campaign)
			}
		default:
			return nil, nativeCampaignStateConflict(campaign)
		}
	case "failed", "interrupted":
		if campaign.State != "running" && campaign.State != "stopping" {
			return nil, nativeCampaignStateConflict(campaign)
		}
	}

	switch cmd.CleanupStatus {
	case "not_required", "pending", "verified", "unknown", "failed":
	default:
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid cleanup status %q", cmd.CleanupStatus)
	}
	switch cmd.TargetState {
	case "paused", "completed":
		if cmd.CleanupStatus != "verified" {
			return nil, nativeCampaignErrorf("state_conflict", 409, "%s requires verified cleanup", cmd.TargetState)
		}
	case "cancelled":
		if cmd.CleanupStatus != "verified" && cmd.CleanupStatus != "not_required" {
			return nil, nativeCampaignErrorf("state_conflict", 409, "cancelled requires verified/not-required cleanup")
		}
	case "failed", "interrupted":
		// unknown/failed cleanup is recorded and keeps resource_hold=true.
	}
	if cmd.CleanupStatus == "not_required" {
		// not_required means "no owned resource was ever created". It is not a
		// shortcut for an arbitrary final to release a hold.
		if attempt.StartedAt != nil {
			return nil, nativeCampaignErrorf("state_conflict", 409,
				"not_required cleanup is invalid after the attempt started")
		}
		var owned map[string]json.RawMessage
		if len(attempt.OwnedResources) > 0 {
			if err := json.Unmarshal(attempt.OwnedResources, &owned); err != nil {
				return nil, nativeCampaignErrorf("state_conflict", 409, "attempt owned_resources is not an object")
			}
		}
		if len(owned) != 0 {
			return nil, nativeCampaignErrorf("state_conflict", 409,
				"not_required cleanup is invalid when owned resources exist")
		}
	}
	if cmd.TargetState == "paused" && cmd.CheckpointID == nil {
		return nil, nativeCampaignErrorf("state_conflict", 409, "paused requires a verified checkpoint")
	}
	if cmd.CheckpointID != nil {
		var checkpointState string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM native_campaign_checkpoints
			WHERE id=$1 AND task_id=$2 AND campaign_id=$3 AND attempt_id=$4`,
			*cmd.CheckpointID, cmd.TaskID, cmd.CampaignID, cmd.AttemptID).Scan(&checkpointState); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nativeCampaignNotFound("checkpoint")
			}
			return nil, err
		}
		if checkpointState != "verified" {
			return nil, nativeCampaignErrorf("state_conflict", 409, "checkpoint is not verified")
		}
	}
	// File bytes are already durable. Publish their index only inside this
	// successful fenced settlement; any later SQL/CAS/commit failure rolls it back.
	if cmd.EvidenceInput != nil {
		// Preserve the ownership/live-lease gate previously enforced by the
		// separate preparation transaction. Old EvidenceID compatibility stays
		// unchanged; terminal idempotent replies have already returned above.
		if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID || !attempt.ResourceHold {
			return nil, nativeCampaignLeaseLostErr("final evidence ownership changed")
		}
		var evidenceNow time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&evidenceNow); err != nil {
			return nil, err
		}
		if !evidenceNow.Before(attempt.LeaseExpiresAt) {
			return nil, nativeCampaignLeaseLostErr("final evidence lease expired")
		}
		evidence, err := insertNativeCampaignEvidenceTx(ctx, tx, *cmd.EvidenceInput)
		if err != nil {
			return nil, err
		}
		cmd.EvidenceID = evidence.ID
	}
	var evidenceExists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM native_campaign_evidence
		WHERE id=$1 AND task_id=$2 AND campaign_id=$3 AND attempt_id=$4)`,
		cmd.EvidenceID, cmd.TaskID, cmd.CampaignID, cmd.AttemptID).Scan(&evidenceExists); err != nil {
		return nil, err
	}
	if !evidenceExists {
		return nil, nativeCampaignNotFound("evidence")
	}

	// Anything short of verified/not-required is treated as an unknown cleanup
	// for settlement: pending means cleanup has not been confirmed either.
	cleanupUnknown := cmd.CleanupStatus == "unknown" || cmd.CleanupStatus == "failed" ||
		cmd.CleanupStatus == "pending"
	settlement, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
		ReservedBudgetMS:  attempt.ReservedBudgetMS,
		ElapsedMS:         cmd.ActualElapsedMS,
		CleanupElapsedMS:  cmd.CleanupElapsedMS,
		CleanupReserveMS:  cmd.CleanupReserveMS,
		CampaignChargedMS: campaign.ChargedBudgetMS,
		CampaignTotalMS:   campaign.TotalBudgetMS,
		FinalLost:         cmd.FinalLost,
		CleanupUnknown:    cleanupUnknown,
	})
	if err != nil {
		return nil, err
	}
	hold := cleanupUnknown || cmd.CleanupStatus == "pending"
	var holdReason any
	if hold {
		switch cmd.CleanupStatus {
		case "pending":
			holdReason = "pending"
		case "failed":
			holdReason = "cleanup_failed"
		default:
			holdReason = "cleanup_unknown"
		}
	}
	terminationReason := cmd.TerminationReason
	if terminationReason == "" {
		terminationReason = cmd.TargetState
	}
	var checkpointID any
	if cmd.CheckpointID != nil {
		checkpointID = *cmd.CheckpointID
	}
	var rawAttempt []byte
	err = tx.QueryRowContext(ctx, `WITH a AS (
		UPDATE native_campaign_attempts SET
			state=$7, phase=$8, charged_budget_ms=$9, actual_elapsed_ms=$10,
			cleanup_status=$11, resource_hold=$12, hold_reason=$13,
			checkpoint_id=COALESCE($14,checkpoint_id), evidence_manifest_id=$15,
			termination_reason=$16, ended_at=now(), cleanup_overrun_ms=$17, budget_overrun=$18,
            owned_resources=CASE WHEN $21::jsonb IS NULL THEN owned_resources ELSE jsonb_set(owned_resources,'{creation_seal}',$21::jsonb,true) END
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3 AND fencing_token=$4
		  AND lease_owner=$5 AND lease_instance=$6 AND state=$19
		  AND lease_expires_at > now()
        AND ($20::jsonb IS NULL OR owned_resources=$20::jsonb)
		RETURNING *) SELECT row_to_json(a) FROM a`,
		cmd.TaskID, cmd.CampaignID, cmd.AttemptID, cmd.FencingToken, cmd.LeaseOwner,
		cmd.LeaseInstance, cmd.TargetState, cmd.Phase, settlement.LedgerMS,
		cmd.ActualElapsedMS, cmd.CleanupStatus, hold, holdReason, checkpointID,
		cmd.EvidenceID, terminationReason, settlement.CleanupOverrunMS,
		cmd.BudgetOverrun || settlement.BudgetOverrun, attempt.State, expectedResources, sealValue).Scan(&rawAttempt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &NativeCampaignError{Code: "lease_lost", Status: 409, Message: "fenced attempt update matched no row"}
	}
	if err != nil {
		return nil, err
	}
	var finalAttempt NativeCampaignAttempt
	if err := json.Unmarshal(rawAttempt, &finalAttempt); err != nil {
		return nil, err
	}

	desired := "none"
	switch cmd.TargetState {
	case "paused":
		desired = "paused"
	case "cancelled":
		desired = "cancelled"
	}
	pauseOrigin := "none"
	if cmd.TargetState == "paused" {
		pauseOrigin = "running"
	}
	var checkpointAny any
	if cmd.CheckpointID != nil {
		checkpointAny = *cmd.CheckpointID
	}
	var rawCampaign []byte
	err = tx.QueryRowContext(ctx, `WITH c AS (
		UPDATE native_campaigns SET
			state=$3, desired_state=$4, state_version=state_version+1,
			charged_budget_ms=$5, cleanup_status=$6, current_attempt_id=$7,
			latest_checkpoint_id=COALESCE($8,latest_checkpoint_id),
			pause_origin=$9, termination_reason=$10,
			last_error_code=$11, last_error_message=$12, ended_at=now()
		WHERE task_id=$1 AND id=$2 AND state_version=$13
		RETURNING *) SELECT row_to_json(c) FROM c`,
		cmd.TaskID, cmd.CampaignID, cmd.TargetState, desired,
		settlement.CampaignChargedMS, cmd.CleanupStatus, cmd.AttemptID, checkpointAny,
		pauseOrigin, terminationReason, nativeCampaignNullableText(cmd.ErrorCode),
		nativeCampaignNullableText(cmd.ErrorMessage), campaign.StateVersion).Scan(&rawCampaign)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignStateConflict(campaign)
	}
	if err != nil {
		return nil, err
	}
	var finalCampaign NativeCampaign
	if err := json.Unmarshal(rawCampaign, &finalCampaign); err != nil {
		return nil, err
	}

	if err := updateNativeCampaignRunLedgerTx(ctx, tx, cmd.TaskID, attempt, cmd.TargetState); err != nil {
		return nil, err
	}
	budgetPayload, _ := json.Marshal(map[string]any{
		"reserved_ms": settlement.ReservedBudgetMS, "charged_ms": settlement.LedgerMS,
		"actual_elapsed_ms":  settlement.ActualElapsedMS,
		"cleanup_overrun_ms": settlement.CleanupOverrunMS,
		"budget_overrun":     settlement.BudgetOverrun || cmd.BudgetOverrun,
	})
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "budget.charged", Payload: budgetPayload,
	}); err != nil {
		return nil, err
	}
	attemptPayload, _ := json.Marshal(map[string]any{
		"state": cmd.TargetState, "reason": terminationReason, "cleanup_status": cmd.CleanupStatus,
	})
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "attempt." + cmd.TargetState, Payload: attemptPayload,
	}); err != nil {
		return nil, err
	}
	if cleanupUnknown {
		cleanupPayload, _ := json.Marshal(map[string]any{
			"cleanup_status": cmd.CleanupStatus, "resource_hold": hold,
		})
		if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
			Kind: "cleanup.unknown", Payload: cleanupPayload,
		}); err != nil {
			return nil, err
		}
	}
	campaignPayload, _ := json.Marshal(map[string]any{
		"termination_reason": terminationReason, "cleanup_status": cmd.CleanupStatus,
	})
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "campaign." + cmd.TargetState, Payload: campaignPayload,
	}); err != nil {
		return nil, err
	}
	if lostRaceEvent != "" {
		payload, _ := json.Marshal(map[string]any{"final_state": "completed"})
		if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
			Kind: lostRaceEvent, Payload: payload,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignFinalizeResult{
		Campaign: &finalCampaign, Attempt: &finalAttempt, Settlement: *settlement,
	}, nil
}

func nativeCampaignNullableText(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nativeCampaignRunStatus(target string) string {
	switch target {
	case "paused":
		return "paused"
	case "completed":
		return "completed"
	case "cancelled":
		return "cancelled"
	case "interrupted":
		return "interrupted"
	default:
		return "failed"
	}
}

func updateNativeCampaignRunLedgerTx(ctx context.Context, tx *sql.Tx, taskID int64, attempt *NativeCampaignAttempt, target string) error {
	status := nativeCampaignRunStatus(target)
	if _, err := tx.ExecContext(ctx, `UPDATE reverse_runtime_runs
		SET status=$3, finished_at=now() WHERE id=$1 AND task_id=$2`,
		attempt.RuntimeRunID, taskID, status); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE reverse_native_runs
		SET target_state=$3 WHERE run_id=$1 AND task_id=$2`,
		attempt.NativeRunID, taskID, target); err != nil {
		return err
	}
	return nil
}

// RetryNativeCampaignCleanup releases a confirmed cleanup without changing the
// failed state or executing anything. An interrupted campaign moves to
// cancelled only after verified cleanup (spec 4.2 #23b); failed stays failed.
func (d *DB) RetryNativeCampaignCleanup(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignCleanupCommand) (*NativeCampaignCleanupResult, error) {
	return d.retryNativeCampaignCleanup(ctx, auth, cmd, nil, false)
}

// SettleUnsealedNativeCampaignCleanup is the explicit operator path for an attempt
// whose final frame was lost before the creation seal was recorded. The caller must
// have verified that every planned container is absent and the staging directory is
// gone; this function never infers that from the run outcome, never transfers
// ownership and never creates a resource. It only releases the held slot.
func (d *DB) SettleUnsealedNativeCampaignCleanup(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignCleanupCommand) (*NativeCampaignCleanupResult, error) {
	return d.retryNativeCampaignCleanup(ctx, auth, cmd, nil, true)
}
func (d *DB) retryNativeCampaignCleanup(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignCleanupCommand, expected *NativeCampaignCleanupExpectation, allowUnsealedPlan bool) (*NativeCampaignCleanupResult, error) {
	if cmd.TaskID <= 0 || cmd.CampaignID <= 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "task_id and campaign_id are required")
	}
	if cmd.CleanupElapsedMS < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "cleanup_elapsed_ms must be non-negative")
	}
	if auth == nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "an explicit campaign authorizer is required")
	}
	if err := auth(ctx, NativeCampaignAuthorizationRequest{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, Action: "cleanup_retry",
		ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
	}); err != nil {
		if NativeCampaignErrorCode(err) == "archive_restore_not_executable" {
			return nil, err
		}
		return nil, &NativeCampaignError{Code: "authorization_revoked", Status: 403, Message: "campaign authorization denied"}
	}
	if !cmd.CleanupVerified {
		return nil, &NativeCampaignError{Code: "cleanup_unknown", Status: 503, Message: "cleanup probe did not verify cleanup"}
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin cleanup retry transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignOwnedSettlement); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignNotFound("campaign")
	}
	if err != nil {
		return nil, err
	}
	if campaign.State != "failed" && campaign.State != "interrupted" {
		return nil, nativeCampaignStateConflict(campaign)
	}
	var attempt *NativeCampaignAttempt
	if cmd.AttemptID > 0 {
		attempt, err = loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, cmd.AttemptID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nativeCampaignNotFound("attempt")
		}
		if err != nil {
			return nil, err
		}
	} else {
		var attemptID int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM native_campaign_attempts
			WHERE task_id=$1 AND campaign_id=$2 AND resource_hold
			ORDER BY attempt_no DESC LIMIT 1`, cmd.TaskID, cmd.CampaignID).Scan(&attemptID); err != nil {
			return nil, nativeCampaignNotFound("held attempt")
		}
		attempt, err = loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, attemptID)
		if err != nil {
			return nil, err
		}
	}
	if attempt.State != "failed" && attempt.State != "interrupted" {
		return nil, &NativeCampaignError{
			Code: "state_conflict", Status: 409, Message: "cleanup retry only applies to failed/interrupted attempts",
			State: campaign.State, StateVersion: campaign.StateVersion,
			Details: map[string]any{"attempt_state": attempt.State},
		}
	}
	// The legacy boolean verdict carries no sealed CID-set proof. Detect the
	// key, not a valid schema: null/unknown plans must not downgrade to legacy.
	var ownedResources map[string]json.RawMessage
	if err := json.Unmarshal(attempt.OwnedResources, &ownedResources); err != nil {
		return nil, nativeCampaignErrorf("cleanup_unknown", 503, "owned resource snapshot is invalid")
	}
	if _, planned := ownedResources["resource_plan"]; planned {
		if expected == nil {
			// Unsealed operator settlement: the plan exists but no creation seal was ever
			// recorded (the final frame was lost before sealing). The caller has already
			// verified that every planned container is absent and staging is gone, so the
			// only remaining effect is releasing the held slot.
			if !allowUnsealedPlan {
				return nil, nativeCampaignErrorf("cleanup_unknown", 503, "resource plan requires sealed cleanup verification")
			}
			seal := ownedResources["creation_seal"]
			if len(seal) != 0 && string(seal) != "null" {
				return nil, nativeCampaignErrorf("state_conflict", 409, "sealed attempt requires the sealed cleanup path")
			}
			if !attempt.ResourceHold || attempt.CleanupStatus != "unknown" {
				return nil, nativeCampaignErrorf("state_conflict", 409, "attempt does not hold an unsettled cleanup")
			}
			switch attempt.State {
			case "failed", "interrupted", "cancelled":
			default:
				return nil, nativeCampaignErrorf("state_conflict", 409, "unsealed settlement needs a terminal attempt")
			}
		} else {
			if !nativeCampaignSealedCleanupState(campaign, attempt) || attempt.FencingToken != expected.FencingToken || campaign.StateVersion != expected.StateVersion || len(ownedResources["creation_seal"]) == 0 || string(ownedResources["creation_seal"]) == "null" {
				return nil, nativeCampaignErrorf("state_conflict", 409, "sealed cleanup snapshot changed")
			}
			var same bool
			if err := tx.QueryRowContext(ctx, `SELECT owned_resources=$4::jsonb FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2 AND id=$3`, cmd.TaskID, cmd.CampaignID, attempt.ID, string(expected.OwnedResources)).Scan(&same); err != nil {
				return nil, err
			}
			if !same {
				return nil, nativeCampaignErrorf("state_conflict", 409, "sealed cleanup resources changed")
			}
		}
	} else if expected != nil {
		return nil, nativeCampaignErrorf("cleanup_unknown", 503, "sealed cleanup cannot downgrade to legacy resources")
	}
	cleanupOverrun := int64(0)
	if cmd.CleanupElapsedMS > NativeCampaignOverheadReserveMS {
		cleanupOverrun = cmd.CleanupElapsedMS - NativeCampaignOverheadReserveMS
	}
	if cmd.CleanupElapsedMS > NativeCampaignCleanupHardTimeoutMS {
		// Record the overrun fact but keep the hold and the failed/interrupted
		// state. A timed-out probe is not verification.
		if _, err := tx.ExecContext(ctx, `UPDATE native_campaign_attempts
			SET cleanup_overrun_ms=GREATEST(cleanup_overrun_ms,$4),
				cleanup_status='unknown', resource_hold=true, hold_reason='cleanup_unknown'
			WHERE task_id=$1 AND campaign_id=$2 AND id=$3`,
			cmd.TaskID, cmd.CampaignID, attempt.ID, cleanupOverrun); err != nil {
			return nil, err
		}
		payload, _ := json.Marshal(map[string]any{
			"hard_timeout": true, "cleanup_elapsed_ms": cmd.CleanupElapsedMS,
			"cleanup_overrun_ms": cleanupOverrun, "resource_hold": true,
		})
		if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &attempt.ID,
			Kind: "cleanup.unknown", Payload: payload,
		}); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, &NativeCampaignError{
			Code: "cleanup_unknown", Status: 503,
			Message: "cleanup exceeded the 60s hard timeout; no hold was released",
			Details: map[string]any{"cleanup_elapsed_ms": cmd.CleanupElapsedMS},
		}
	}
	var rawAttempt []byte
	err = tx.QueryRowContext(ctx, `WITH a AS (
		UPDATE native_campaign_attempts SET cleanup_status='verified',
			resource_hold=false, hold_reason=NULL,
			cleanup_overrun_ms=GREATEST(cleanup_overrun_ms,$4)
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3 AND resource_hold
		RETURNING *) SELECT row_to_json(a) FROM a`,
		cmd.TaskID, cmd.CampaignID, attempt.ID, cleanupOverrun).Scan(&rawAttempt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &NativeCampaignError{Code: "state_conflict", Status: 409, Message: "cleanup hold was already released"}
	}
	if err != nil {
		return nil, err
	}
	var finalAttempt NativeCampaignAttempt
	if err := json.Unmarshal(rawAttempt, &finalAttempt); err != nil {
		return nil, err
	}
	targetState := campaign.State
	desired := "none"
	if campaign.State == "interrupted" {
		targetState = "cancelled"
		desired = "cancelled"
	}
	var rawCampaign []byte
	err = tx.QueryRowContext(ctx, `WITH c AS (
		UPDATE native_campaigns SET cleanup_status='verified', state=$3,
			desired_state=$4, state_version=state_version+1,
			termination_reason=CASE WHEN $3='cancelled' THEN 'cancelled' ELSE termination_reason END,
			ended_at=CASE WHEN $3='cancelled' THEN now() ELSE ended_at END
		WHERE task_id=$1 AND id=$2 AND state=$5
		RETURNING *) SELECT row_to_json(c) FROM c`,
		cmd.TaskID, cmd.CampaignID, targetState, desired, campaign.State).Scan(&rawCampaign)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignStateConflict(campaign)
	}
	if err != nil {
		return nil, err
	}
	var finalCampaign NativeCampaign
	if err := json.Unmarshal(rawCampaign, &finalCampaign); err != nil {
		return nil, err
	}
	if campaign.State == "interrupted" {
		if err := updateNativeCampaignRunLedgerTx(ctx, tx, cmd.TaskID, attempt, "cancelled"); err != nil {
			return nil, err
		}
	}
	payload, _ := json.Marshal(map[string]any{
		"success": true, "cleanup_elapsed_ms": cmd.CleanupElapsedMS, "state": targetState,
	})
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &attempt.ID,
		Kind: "cleanup.retry", Payload: payload,
	}); err != nil {
		return nil, err
	}
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &attempt.ID,
		Kind: "cleanup.verified", Payload: payload,
	}); err != nil {
		return nil, err
	}
	if campaign.State == "interrupted" {
		if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &attempt.ID,
			Kind: "campaign.cancelled", Payload: payload,
		}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignCleanupResult{Campaign: &finalCampaign, Attempt: &finalAttempt}, nil
}
