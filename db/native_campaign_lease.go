package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Native Campaign v1 (T4a) lease CAS helpers.
//
// These helpers are intentionally separate from the T3 state machine. They only
// cover the narrow operations the single-worker manager needs between claim and
// finalize:
//
//   - renew a live lease using the database clock, never reviving an expired or
//     terminal token;
//   - persist started_at / owned_resources / phase before any owned resource is
//     launched, with a fenced CAS so a stale worker cannot start after losing
//     ownership;
//   - halt an attempt whose lease was lost and keep the global resource hold for
//     reconciliation.
//
// Nothing here releases resource_hold. Only a verified cleanup or the T3
// finalize/cleanup-retry path may do that. No schema change is required.

// NativeCampaignLeaseIdentity is the ownership tuple checked by every lease CAS.
type NativeCampaignLeaseIdentity struct {
	TaskID        int64  `json:"task_id"`
	CampaignID    int64  `json:"campaign_id"`
	AttemptID     int64  `json:"attempt_id"`
	FencingToken  int64  `json:"fencing_token"`
	LeaseOwner    string `json:"lease_owner"`
	LeaseInstance string `json:"lease_instance"`
}

// NativeCampaignLeaseCommand is a bounded lease renewal request.
type NativeCampaignLeaseCommand struct {
	NativeCampaignLeaseIdentity
	LeaseMS int64 `json:"lease_ms"`
}

// NativeCampaignAttemptStartCommand marks an attempt as launching and persists
// the planned owned resources before the runner factory is allowed to start.
type NativeCampaignAttemptStartCommand struct {
	NativeCampaignLeaseIdentity
	Phase          string          `json:"phase"`
	OwnedResources json.RawMessage `json:"owned_resources"`
}

// NativeCampaignLeaseHaltCommand records that this worker lost or gave up the
// lease. It never claims cleanup and always keeps resource_hold=true.
type NativeCampaignLeaseHaltCommand struct {
	NativeCampaignLeaseIdentity
	Reason          string `json:"reason"`
	ActualElapsedMS int64  `json:"actual_elapsed_ms"`
}

// NativeCampaignLeaseResult is the fenced outcome of a lease CAS.
type NativeCampaignLeaseResult struct {
	Attempt        *NativeCampaignAttempt `json:"attempt"`
	Campaign       *NativeCampaign        `json:"campaign,omitempty"`
	LeaseExpiresAt time.Time              `json:"lease_expires_at"`
}

func validateNativeCampaignLeaseIdentity(id NativeCampaignLeaseIdentity) error {
	if id.TaskID <= 0 || id.CampaignID <= 0 || id.AttemptID <= 0 {
		return nativeCampaignErrorf("invalid_request", 400, "task_id, campaign_id and attempt_id are required")
	}
	if id.FencingToken <= 0 {
		return nativeCampaignErrorf("invalid_request", 400, "fencing_token is required")
	}
	if len(id.LeaseOwner) < 1 || len(id.LeaseOwner) > 64 {
		return nativeCampaignErrorf("invalid_request", 400, "lease_owner must be 1..64 characters")
	}
	if len(id.LeaseInstance) < 1 || len(id.LeaseInstance) > 128 {
		return nativeCampaignErrorf("invalid_request", 400, "lease_instance must be 1..128 characters")
	}
	return nil
}

func nativeCampaignLeaseLostErr(message string) *NativeCampaignError {
	return &NativeCampaignError{Code: "lease_lost", Status: 409, Message: message}
}

// RenewNativeCampaignAttemptLease extends a live lease. The campaign and attempt
// rows are locked in the same order as halt/claim, then clock_timestamp() is
// sampled after the locks are held. A renewal that waited past lease expiry
// therefore cannot revive the token even though now() (transaction start time)
// would still be before expiry.
func (d *DB) RenewNativeCampaignAttemptLease(ctx context.Context, cmd NativeCampaignLeaseCommand) (*NativeCampaignLeaseResult, error) {
	if err := validateNativeCampaignLeaseIdentity(cmd.NativeCampaignLeaseIdentity); err != nil {
		return nil, err
	}
	leaseMS, err := ValidateNativeCampaignLeaseMS(cmd.LeaseMS)
	if err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin lease renewal transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("campaign does not belong to the task")
	}
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, cmd.AttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt does not belong to the campaign")
	}
	if err != nil {
		return nil, err
	}
	if attempt.FencingToken != cmd.FencingToken || attempt.LeaseOwner != cmd.LeaseOwner ||
		attempt.LeaseInstance != cmd.LeaseInstance {
		return nil, nativeCampaignLeaseLostErr("fencing token or lease identity does not match")
	}
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID ||
		(campaign.State != "running" && campaign.State != "stopping") {
		return nil, nativeCampaignLeaseLostErr("attempt is not the current running campaign attempt")
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("attempt is terminal and cannot be renewed")
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return nil, err
	}
	if !dbNow.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("attempt lease has expired")
	}
	expires := dbNow.Add(time.Duration(leaseMS) * time.Millisecond)
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH renewed AS (
		UPDATE native_campaign_attempts
		SET lease_expires_at=$7
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3
		  AND fencing_token=$4 AND lease_owner=$5 AND lease_instance=$6
		  AND state IN ('claimed','launching','running','stopping','collecting','cleaning')
		RETURNING *) SELECT row_to_json(renewed) FROM renewed`,
		cmd.TaskID, cmd.CampaignID, cmd.AttemptID, cmd.FencingToken,
		cmd.LeaseOwner, cmd.LeaseInstance, expires).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt lease cannot be renewed: ownership or state changed")
	}
	if err != nil {
		return nil, err
	}
	var renewed NativeCampaignAttempt
	if err := json.Unmarshal(raw, &renewed); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignLeaseResult{Attempt: &renewed, LeaseExpiresAt: renewed.LeaseExpiresAt}, nil
}

// CheckNativeCampaignAttemptStart is the read-only start-permission gate. It is
// deliberately separate from RenewNativeCampaignAttemptLease: a renewal is
// allowed while the campaign is stopping, but a runner may only be started while
// the campaign is still running and this exact attempt/fence/owner/instance
// holds the current, unexpired lease. The database clock is sampled after the
// row locks so a waiter that outlived the lease cannot pass this gate.
func (d *DB) CheckNativeCampaignAttemptStart(ctx context.Context, id NativeCampaignLeaseIdentity) (*NativeCampaignLeaseResult, error) {
	if err := validateNativeCampaignLeaseIdentity(id); err != nil {
		return nil, err
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin start-permission transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, id.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, id.TaskID, id.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, id.TaskID, id.CampaignID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("campaign does not belong to the task")
	}
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, id.TaskID, id.CampaignID, id.AttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt does not belong to the campaign")
	}
	if err != nil {
		return nil, err
	}
	if attempt.FencingToken != id.FencingToken || attempt.LeaseOwner != id.LeaseOwner ||
		attempt.LeaseInstance != id.LeaseInstance {
		return nil, nativeCampaignLeaseLostErr("fencing token or lease identity does not match")
	}
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID {
		return nil, nativeCampaignLeaseLostErr("attempt is not the campaign current attempt")
	}
	// Renew may continue while stopping, but Start must not. A pause/cancel that
	// committed between the factory and the final Start call is rejected here.
	if campaign.State != "running" || campaign.DesiredState != "running" {
		return nil, nativeCampaignLeaseLostErr("campaign is no longer running/desired running")
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("attempt is terminal and cannot be started")
	}
	if attempt.StartedAt == nil {
		return nil, nativeCampaignLeaseLostErr("attempt has not been persisted as started")
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return nil, err
	}
	if !dbNow.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("attempt lease has expired before start")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignLeaseResult{
		Attempt: attempt, Campaign: campaign, LeaseExpiresAt: attempt.LeaseExpiresAt,
	}, nil
}

// MarkNativeCampaignAttemptStarted is the fenced "about to launch" CAS. It locks
// campaign then attempt, samples clock_timestamp() after the locks, sets
// started_at exactly once, persists phase/owned_resources and moves claimed ->
// launching. If it returns an error the caller must not start a runner.
func (d *DB) MarkNativeCampaignAttemptStarted(ctx context.Context, cmd NativeCampaignAttemptStartCommand) (*NativeCampaignLeaseResult, error) {
	if err := validateNativeCampaignLeaseIdentity(cmd.NativeCampaignLeaseIdentity); err != nil {
		return nil, err
	}
	if _, ok := nativeCampaignValidPhases[cmd.Phase]; !ok {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid attempt phase %q", cmd.Phase)
	}
	owned, err := normalizeNativeCampaignJSONObject(cmd.OwnedResources, 16384, "owned_resources")
	if err != nil {
		return nil, nativeCampaignErrorf("invalid_request", 400, "owned_resources: %v", err)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin attempt-start transaction: %v", err)
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignNewWrite); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("campaign does not belong to the task")
	}
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, cmd.AttemptID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt does not belong to the campaign")
	}
	if err != nil {
		return nil, err
	}
	if attempt.FencingToken != cmd.FencingToken || attempt.LeaseOwner != cmd.LeaseOwner ||
		attempt.LeaseInstance != cmd.LeaseInstance {
		return nil, nativeCampaignLeaseLostErr("fencing token or lease identity does not match")
	}
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID ||
		campaign.State != "running" || campaign.DesiredState != "running" {
		return nil, nativeCampaignLeaseLostErr("attempt is not the current running campaign attempt")
	}
	if attempt.State != "claimed" || attempt.StartedAt != nil {
		return nil, nativeCampaignLeaseLostErr("attempt was already started or is not claimed")
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return nil, err
	}
	if !dbNow.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("attempt lease has expired before start")
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `WITH started AS (
		UPDATE native_campaign_attempts
		SET state='launching', phase=$7, started_at=$9, owned_resources=$8
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3
		  AND fencing_token=$4 AND lease_owner=$5 AND lease_instance=$6
		  AND state='claimed' AND started_at IS NULL
		RETURNING *) SELECT row_to_json(started) FROM started`,
		cmd.TaskID, cmd.CampaignID, cmd.AttemptID, cmd.FencingToken,
		cmd.LeaseOwner, cmd.LeaseInstance, cmd.Phase, owned, dbNow).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt cannot be marked started: ownership or state changed")
	}
	if err != nil {
		return nil, err
	}
	var started NativeCampaignAttempt
	if err := json.Unmarshal(raw, &started); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignLeaseResult{Attempt: &started, LeaseExpiresAt: started.LeaseExpiresAt}, nil
}

// HaltNativeCampaignAttemptForLeaseLoss transitions an owned but no-longer-trusted
// attempt to interrupted/cleanup_unknown. It deliberately does NOT require the
// lease to be unexpired (the caller invokes it after detecting loss) and never
// releases resource_hold. A late/foreign token, a different current attempt or a
// terminal state other than an idempotent interrupted-unknown row is rejected.
func (d *DB) HaltNativeCampaignAttemptForLeaseLoss(ctx context.Context, cmd NativeCampaignLeaseHaltCommand) (*NativeCampaignLeaseResult, error) {
	return d.haltNativeCampaignAttempt(ctx, cmd, false)
}

// Both an owned worker's lost-lease settlement and restart reconciliation use
// one transaction/settlement implementation. Only restart requires proof that
// the database lease has expired while holding campaign and attempt locks.
func (d *DB) haltNativeCampaignAttempt(ctx context.Context, cmd NativeCampaignLeaseHaltCommand, requireExpired bool) (*NativeCampaignLeaseResult, error) {
	if err := validateNativeCampaignLeaseIdentity(cmd.NativeCampaignLeaseIdentity); err != nil {
		return nil, err
	}
	if cmd.ActualElapsedMS < 0 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "actual_elapsed_ms must be non-negative")
	}
	reason := strings.TrimSpace(cmd.Reason)
	if reason == "" {
		reason = "lease_lost"
	}
	if len(reason) > 128 {
		reason = reason[:128]
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, nativeCampaignErrorf("internal", 500, "begin lease halt transaction: %v", err)
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
		return nil, nativeCampaignLeaseLostErr("fencing token or lease identity does not match")
	}
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID {
		return nil, nativeCampaignLeaseLostErr("attempt is not the campaign current attempt")
	}
	if attempt.State == "interrupted" && attempt.CleanupStatus == "unknown" && attempt.ResourceHold {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &NativeCampaignLeaseResult{Attempt: attempt, Campaign: campaign}, nil
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("attempt is not active and cannot be halted as lost")
	}
	if requireExpired {
		var dbNow time.Time
		if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
			return nil, err
		}
		if dbNow.Before(attempt.LeaseExpiresAt) {
			return nil, nativeCampaignErrorf("lease_active", 409, "attempt still has a live database lease")
		}
		if attempt.StartedAt != nil && dbNow.After(*attempt.StartedAt) {
			cmd.ActualElapsedMS = dbNow.Sub(*attempt.StartedAt).Milliseconds()
		}
	}
	// A lost attempt that already started is conservatively charged its full
	// reservation (T3 settlement rule). Before runner start nothing is charged:
	// authorization revocation in the claim -> start gap must not consume budget.
	chargedDelta := int64(0)
	budgetOverrun := false
	if attempt.StartedAt != nil {
		settlement, err := SettleNativeCampaignBudget(NativeCampaignSettlementInput{
			ReservedBudgetMS:  attempt.ReservedBudgetMS,
			ElapsedMS:         cmd.ActualElapsedMS,
			CampaignChargedMS: campaign.ChargedBudgetMS,
			CampaignTotalMS:   campaign.TotalBudgetMS,
			FinalLost:         true,
			CleanupUnknown:    true,
		})
		if err != nil {
			return nil, err
		}
		chargedDelta = settlement.LedgerMS
		budgetOverrun = settlement.BudgetOverrun
	}
	var rawAttempt []byte
	err = tx.QueryRowContext(ctx, `WITH halted AS (
		UPDATE native_campaign_attempts SET
			state='interrupted', phase='cleanup', cleanup_status='unknown',
			resource_hold=true, hold_reason='cleanup_unknown',
			termination_reason=$7, ended_at=now(),
			actual_elapsed_ms=GREATEST(actual_elapsed_ms,$8),
			charged_budget_ms=$9, budget_overrun=$10
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3
		  AND fencing_token=$4 AND lease_owner=$5 AND lease_instance=$6
		  AND state IN ('claimed','launching','running','stopping','collecting','cleaning')
		RETURNING *) SELECT row_to_json(halted) FROM halted`,
		cmd.TaskID, cmd.CampaignID, cmd.AttemptID, cmd.FencingToken,
		cmd.LeaseOwner, cmd.LeaseInstance, reason, cmd.ActualElapsedMS,
		chargedDelta, budgetOverrun).Scan(&rawAttempt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignLeaseLostErr("attempt halt matched no active owned row")
	}
	if err != nil {
		return nil, err
	}
	var halted NativeCampaignAttempt
	if err := json.Unmarshal(rawAttempt, &halted); err != nil {
		return nil, err
	}
	var rawCampaign []byte
	err = tx.QueryRowContext(ctx, `WITH halted AS (
		UPDATE native_campaigns SET
			state='interrupted', desired_state='none', state_version=state_version+1,
			cleanup_status='unknown', termination_reason=$4, ended_at=now(),
			charged_budget_ms=charged_budget_ms+$6,
			last_error_code='lease_lost', last_error_message=$5
		WHERE task_id=$1 AND id=$2 AND current_attempt_id=$3
		  AND state IN ('running','stopping')
		RETURNING *) SELECT row_to_json(halted) FROM halted`,
		cmd.TaskID, cmd.CampaignID, cmd.AttemptID, reason,
		"campaign worker could not prove continuous lease ownership", chargedDelta).Scan(&rawCampaign)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, &NativeCampaignError{
			Code: "state_conflict", Status: 409,
			Message: "campaign is no longer running/stopping for this attempt",
			State:   campaign.State, StateVersion: campaign.StateVersion,
		}
	}
	if err != nil {
		return nil, err
	}
	var haltedCampaign NativeCampaign
	if err := json.Unmarshal(rawCampaign, &haltedCampaign); err != nil {
		return nil, err
	}
	if err := updateNativeCampaignRunLedgerTx(ctx, tx, cmd.TaskID, attempt, "interrupted"); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(map[string]any{
		"reason": reason, "resource_hold": true, "cleanup_status": "unknown",
		"actual_elapsed_ms": cmd.ActualElapsedMS, "charged_ms": chargedDelta,
	})
	if chargedDelta > 0 {
		budgetPayload, _ := json.Marshal(map[string]any{
			"reserved_ms": attempt.ReservedBudgetMS, "charged_ms": chargedDelta,
			"actual_elapsed_ms": cmd.ActualElapsedMS, "lost_or_unknown": true,
			"budget_overrun": budgetOverrun,
		})
		if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
			Kind: "budget.charged", Payload: budgetPayload,
		}); err != nil {
			return nil, err
		}
	}
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "attempt.interrupted", Payload: payload,
	}); err != nil {
		return nil, err
	}
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "cleanup.unknown", Payload: payload,
	}); err != nil {
		return nil, err
	}
	if err := insertNativeCampaignEventTx(ctx, tx, NativeCampaignEventInput{
		TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, AttemptID: &cmd.AttemptID,
		Kind: "campaign.interrupted", Payload: payload,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignLeaseResult{
		Attempt: &halted, Campaign: &haltedCampaign,
		LeaseExpiresAt: halted.LeaseExpiresAt,
	}, nil
}
