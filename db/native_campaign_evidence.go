package db

import (
	"context"
	"errors"
	"time"
)

// NativeCampaignPublishedEvidenceList exposes only evidence attached by the
// fenced finalization transaction. CreateNativeCampaignEvidence prepares rows;
// insertion alone is not publication. Prepared rows remain available to the
// internal metadata reader for future safe orphan handling, never deleted here.
func (d *DB) NativeCampaignPublishedEvidenceList(ctx context.Context, taskID, campaignID int64, limit int, beforeID int64) ([]NativeCampaignEvidence, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, errors.New("task_id and campaign_id are required")
	}
	limit = clampNativeCampaignLimit(limit)
	if beforeID < 0 {
		beforeID = 0
	}
	return scanNativeCampaignList[NativeCampaignEvidence](d.QueryContext(ctx, `
 SELECT row_to_json(e) FROM native_campaign_evidence e
 JOIN native_campaign_attempts a ON a.id=e.attempt_id
  AND a.task_id=e.task_id AND a.campaign_id=e.campaign_id
  AND a.evidence_manifest_id=e.id
 WHERE e.task_id=$1 AND e.campaign_id=$2 AND ($4=0 OR e.id<$4)
  AND a.state IN ('paused','completed','cancelled','failed','interrupted')
  AND a.ended_at IS NOT NULL
 ORDER BY e.id DESC LIMIT $3`, taskID, campaignID, limit, beforeID))
}

// PrepareNativeCampaignFinalEvidence is the owned-settlement counterpart to the
// ordinary metadata API. It does not publish: Finalize still attaches by fence.
func (d *DB) PrepareNativeCampaignFinalEvidence(ctx context.Context, id NativeCampaignLeaseIdentity, in NativeCampaignEvidenceInput) (*NativeCampaignEvidence, error) {
	if err := validateNativeCampaignLeaseIdentity(id); err != nil {
		return nil, err
	}
	if in.TaskID != id.TaskID || in.CampaignID != id.CampaignID || in.AttemptID != id.AttemptID || in.Kind != "attempt_final" {
		return nil, nativeCampaignErrorf("invalid_request", 400, "final evidence identity mismatch")
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
	if campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID || (campaign.State != "running" && campaign.State != "stopping") || !attempt.ResourceHold || attempt.FencingToken != id.FencingToken || attempt.LeaseOwner != id.LeaseOwner || attempt.LeaseInstance != id.LeaseInstance {
		return nil, nativeCampaignLeaseLostErr("final evidence ownership changed")
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("final evidence attempt is terminal")
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, err
	}
	if !now.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("final evidence lease expired")
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
