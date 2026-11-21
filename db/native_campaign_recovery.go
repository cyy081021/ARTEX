package db

import (
	"context"
	"encoding/json"
	"time"
)

// ReconcileExpiredNativeCampaignAttempt never creates resources or transfers
// ownership. Under the same row locks used by renewal, it rechecks the exact
// observed identity/current attempt and the DB clock. Live owners are busy,
// regardless of their instance ID. Interrupted unknown holds are idempotent.
func (d *DB) ReconcileExpiredNativeCampaignAttempt(ctx context.Context, id NativeCampaignLeaseIdentity) (*NativeCampaignLeaseResult, error) {
	return d.haltNativeCampaignAttempt(ctx, NativeCampaignLeaseHaltCommand{NativeCampaignLeaseIdentity: id, Reason: "restart_lease_expired"}, true)
}

// Cleanup snapshots are read under short campaign->attempt locks. No external
// process or filesystem call occurs while the transaction is open.
type NativeCampaignCleanupSnapshot struct {
	Campaign *NativeCampaign
	Attempt  *NativeCampaignAttempt
}
type NativeCampaignCleanupExpectation struct {
	FencingToken   int64
	StateVersion   int64
	OwnedResources json.RawMessage
}

func (d *DB) NativeCampaignCleanupSnapshot(ctx context.Context, auth NativeCampaignAuthorizer, taskID, campaignID, attemptID int64) (*NativeCampaignCleanupSnapshot, error) {
	if taskID <= 0 || campaignID <= 0 || attemptID <= 0 || auth == nil {
		return nil, nativeCampaignErrorf("invalid_request", 400, "explicit cleanup identity and authorizer required")
	}
	if err := auth(ctx, NativeCampaignAuthorizationRequest{TaskID: taskID, CampaignID: campaignID, Action: "cleanup_retry", ActorKind: "admin"}); err != nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "cleanup authorization denied")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, taskID, nativeCampaignOwnedSettlement); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, taskID, campaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, taskID, campaignID, false)
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, taskID, campaignID, attemptID)
	if err != nil {
		return nil, err
	}
	if !nativeCampaignSealedCleanupState(campaign, attempt) {
		return nil, nativeCampaignErrorf("state_conflict", 409, "cleanup requires the current terminal unknown held attempt")
	}
	var owned map[string]json.RawMessage
	if json.Unmarshal(attempt.OwnedResources, &owned) != nil || len(owned["resource_plan"]) == 0 || len(owned["creation_seal"]) == 0 || string(owned["creation_seal"]) == "null" {
		return nil, nativeCampaignErrorf("cleanup_unknown", 503, "durable creation seal unavailable")
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NativeCampaignCleanupSnapshot{Campaign: campaign, Attempt: attempt}, nil
}
func nativeCampaignSealedCleanupState(campaign *NativeCampaign, attempt *NativeCampaignAttempt) bool {
	return campaign.CurrentAttemptID != nil && *campaign.CurrentAttemptID == attempt.ID &&
		(campaign.State == "failed" || campaign.State == "interrupted") &&
		(attempt.State == "failed" || attempt.State == "interrupted") &&
		attempt.ResourceHold && attempt.CleanupStatus == "unknown" && campaign.CleanupStatus == "unknown"
}

// This separate internal entry requires a server-validated complete probe and
// the original snapshot. The legacy boolean API cannot supply an expectation.
func (d *DB) RetryNativeCampaignSealedCleanup(ctx context.Context, auth NativeCampaignAuthorizer, cmd NativeCampaignCleanupCommand, expected NativeCampaignCleanupExpectation) (*NativeCampaignCleanupResult, error) {
	if cmd.AttemptID <= 0 || expected.FencingToken <= 0 || expected.StateVersion <= 0 || len(expected.OwnedResources) == 0 || len(expected.OwnedResources) > 16384 || !json.Valid(expected.OwnedResources) {
		return nil, nativeCampaignErrorf("invalid_request", 400, "sealed cleanup expectation required")
	}
	return d.retryNativeCampaignCleanup(ctx, auth, cmd, &expected, false)
}

// SealNativeCampaignAttemptCreation records proof before cleanup without
// settling, renewing or releasing anything. The caller has validated the full
// final/Wait/plan binding. This transaction independently fences the handoff.
func (d *DB) SealNativeCampaignAttemptCreation(ctx context.Context, auth NativeCampaignAuthorizer, id NativeCampaignLeaseIdentity, expected, seal json.RawMessage) (*NativeCampaignAttempt, error) {
	if err := validateNativeCampaignLeaseIdentity(id); err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, nativeCampaignErrorf("authorization_revoked", 403, "seal authorizer required")
	}
	if err := auth(ctx, NativeCampaignAuthorizationRequest{TaskID: id.TaskID, CampaignID: id.CampaignID, Action: "finalize", ActorKind: "admin"}); err != nil {
		return nil, err
	}
	var envelope map[string]json.RawMessage
	var proof struct {
		Version      int    `json:"version"`
		TaskID       int64  `json:"task_id"`
		CampaignID   int64  `json:"campaign_id"`
		AttemptID    int64  `json:"attempt_id"`
		FencingToken int64  `json:"fencing_token"`
		PlanSHA256   string `json:"plan_sha256"`
	}
	if len(expected) == 0 || len(expected) > 16384 || len(seal) == 0 || len(seal) > 8192 || json.Unmarshal(expected, &envelope) != nil || len(envelope["resource_plan"]) == 0 || string(envelope["resource_plan"]) == "null" || json.Unmarshal(seal, &proof) != nil || proof.Version != 1 || proof.TaskID != id.TaskID || proof.CampaignID != id.CampaignID || proof.AttemptID != id.AttemptID || proof.FencingToken != id.FencingToken || len(proof.PlanSHA256) != 64 {
		return nil, nativeCampaignErrorf("invalid_request", 400, "invalid immutable creation seal handoff")
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, id.TaskID, nativeCampaignOwnedSettlement); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, id.TaskID, id.CampaignID); err != nil {
		return nil, err
	}

	campaign, err := loadNativeCampaignTx(ctx, tx, id.TaskID, id.CampaignID, false)
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, id.TaskID, id.CampaignID, id.AttemptID)
	if err != nil {
		return nil, err
	}
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID || (campaign.State != "running" && campaign.State != "stopping") || attempt.FencingToken != id.FencingToken || attempt.LeaseOwner != id.LeaseOwner || attempt.LeaseInstance != id.LeaseInstance || !attempt.ResourceHold || attempt.StartedAt == nil {
		return nil, nativeCampaignLeaseLostErr("creation seal ownership changed")
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("creation seal attempt is terminal")
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if !now.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("creation seal lease expired")
	}
	var matches, same, hasSeal bool
	err = tx.QueryRowContext(ctx, `SELECT (owned_resources=$4::jsonb OR (NOT ($4::jsonb ? 'creation_seal') AND owned_resources-'creation_seal'=$4::jsonb)),COALESCE(owned_resources->'creation_seal'=$5::jsonb,false),owned_resources ? 'creation_seal' FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2 AND id=$3`, id.TaskID, id.CampaignID, id.AttemptID, string(expected), string(seal)).Scan(&matches, &same, &hasSeal)
	if err != nil {
		return nil, err
	}
	if !matches || (hasSeal && !same) {
		return nil, nativeCampaignErrorf("state_conflict", 409, "creation plan or immutable seal changed")
	}
	if !hasSeal {
		var raw []byte
		err = tx.QueryRowContext(ctx, `WITH sealed AS (UPDATE native_campaign_attempts SET owned_resources=jsonb_set(owned_resources,'{creation_seal}',$7::jsonb,true) WHERE task_id=$1 AND campaign_id=$2 AND id=$3 AND fencing_token=$4 AND lease_owner=$5 AND lease_instance=$6 AND lease_expires_at>clock_timestamp() AND owned_resources=$8::jsonb RETURNING *) SELECT row_to_json(sealed) FROM sealed`, id.TaskID, id.CampaignID, id.AttemptID, id.FencingToken, id.LeaseOwner, id.LeaseInstance, string(seal), string(expected)).Scan(&raw)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, attempt); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return attempt, nil
}
