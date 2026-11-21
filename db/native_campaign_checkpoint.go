package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// NativeCampaignCheckpointCommit describes already durably verified CAS files.
// File publication precedes this transaction; SQL failure may leave unreferenced
// immutable files. It must never be reported as an atomic filesystem/DB commit.
type NativeCampaignCheckpointCommit struct {
	NativeCampaignLeaseIdentity
	Manifest NativeCampaignManifestInput
}

// CommitVerifiedNativeCampaignCheckpoint atomically installs the object metadata,
// manifest, entries and verified checkpoint. It does not finalize the attempt or
// release resource_hold. The ordinary fenced finalizer still owns that decision.
func (d *DB) CommitVerifiedNativeCampaignCheckpoint(ctx context.Context, cmd NativeCampaignCheckpointCommit) (*NativeCampaignCheckpoint, error) {
	if err := validateNativeCampaignLeaseIdentity(cmd.NativeCampaignLeaseIdentity); err != nil {
		return nil, err
	}
	in := cmd.Manifest
	if len(in.Entries) < 1 || len(in.Entries) > 512 {
		return nil, errors.New("checkpoint entry count outside 1..512")
	}
	// Do not mutate the caller's manifest slice while assigning database IDs.
	in.Entries = append([]NativeCampaignEntryInput(nil), in.Entries...)
	if in.TaskID != cmd.TaskID || in.CampaignID != cmd.CampaignID || in.AttemptID != cmd.AttemptID {
		return nil, errors.New("checkpoint manifest identity mismatch")
	}
	if err := validateNativeCampaignManifestInput(&in, false); err != nil {
		return nil, err
	}
	unique := make(map[string]bool, len(in.Entries))
	for _, entry := range in.Entries {
		if unique[entry.SHA256] {
			return nil, errors.New("duplicate checkpoint object")
		}
		unique[entry.SHA256] = true
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := admitNativeCampaignWriteTx(ctx, tx, cmd.TaskID, nativeCampaignOwnedSettlement); err != nil {
		return nil, err
	}
	if err := rejectNativeCampaignArchiveRestoredTx(ctx, tx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	// Serialize task object quota with other invocations of this API. The caller
	// separately holds its stable task filesystem lock across publication/commit.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('artex-campaign-cas:' || $1::bigint::text, 0))`, cmd.TaskID); err != nil {
		return nil, err
	}
	campaign, err := loadNativeCampaignTx(ctx, tx, cmd.TaskID, cmd.CampaignID, false)
	if err != nil {
		return nil, err
	}
	attempt, err := loadNativeCampaignAttemptTx(ctx, tx, cmd.TaskID, cmd.CampaignID, cmd.AttemptID)
	if err != nil {
		return nil, err
	}
	if attempt.FencingToken != cmd.FencingToken || attempt.LeaseOwner != cmd.LeaseOwner || attempt.LeaseInstance != cmd.LeaseInstance || !attempt.ResourceHold || campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID || (campaign.State != "running" && campaign.State != "stopping") {
		return nil, nativeCampaignLeaseLostErr("checkpoint ownership changed")
	}
	if _, active := nativeCampaignActiveAttemptStates[attempt.State]; !active {
		return nil, nativeCampaignLeaseLostErr("checkpoint attempt is terminal")
	}
	var dbNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&dbNow); err != nil {
		return nil, err
	}
	if !dbNow.Before(attempt.LeaseExpiresAt) {
		return nil, nativeCampaignLeaseLostErr("checkpoint lease expired")
	}
	var existingRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT row_to_json(c) FROM native_campaign_checkpoints c WHERE task_id=$1 AND campaign_id=$2 AND attempt_id=$3`, cmd.TaskID, cmd.CampaignID, cmd.AttemptID).Scan(&existingRaw)
	if err == nil {
		var existing NativeCampaignCheckpoint
		if err := json.Unmarshal(existingRaw, &existing); err != nil {
			return nil, err
		}
		var digest string
		if err := tx.QueryRowContext(ctx, `SELECT manifest_sha256 FROM native_campaign_corpus_manifests WHERE id=$1 AND task_id=$2 AND campaign_id=$3 AND attempt_id=$4`, existing.ManifestID, cmd.TaskID, cmd.CampaignID, cmd.AttemptID).Scan(&digest); err != nil {
			return nil, err
		}
		if existing.State != "verified" || existing.EntryCount != in.EntryCount || existing.TotalBytes != in.TotalBytes || existing.Truncated != in.Truncated || digest != in.ManifestSHA256 {
			return nil, errors.New("existing checkpoint conflicts with immutable content")
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	for i := range in.Entries {
		entry := &in.Entries[i]
		err := tx.QueryRowContext(ctx, `INSERT INTO native_campaign_objects(task_id,sha256,length,storage_key) VALUES($1,$2,$3,$4)
   ON CONFLICT(task_id,sha256,length) DO NOTHING RETURNING id`, cmd.TaskID, entry.SHA256, entry.Length, entry.StorageKey).Scan(&entry.ObjectID)
		if errors.Is(err, sql.ErrNoRows) {
			var key string
			err = tx.QueryRowContext(ctx, `SELECT id,storage_key FROM native_campaign_objects WHERE task_id=$1 AND sha256=$2 AND length=$3`, cmd.TaskID, entry.SHA256, entry.Length).Scan(&entry.ObjectID, &key)
			if err == nil && key != entry.StorageKey {
				return nil, errors.New("existing object storage key mismatch")
			}
		}
		if err != nil {
			return nil, err
		}
	}
	var count, bytes int64
	if err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(sum(length),0) FROM native_campaign_objects WHERE task_id=$1`, cmd.TaskID).Scan(&count, &bytes); err != nil {
		return nil, err
	}
	if count > 16384 || bytes > 512<<20 {
		return nil, nativeCampaignErrorf("quota_exceeded", 409, "campaign object quota exceeded")
	}
	var manifestID int64
	if err := tx.QueryRowContext(ctx, `INSERT INTO native_campaign_corpus_manifests(task_id,campaign_id,attempt_id,manifest_sha256,entry_count,total_bytes,truncated)
  VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, cmd.TaskID, cmd.CampaignID, cmd.AttemptID, in.ManifestSHA256, in.EntryCount, in.TotalBytes, in.Truncated).Scan(&manifestID); err != nil {
		return nil, err
	}
	for _, entry := range in.Entries {
		if _, err := tx.ExecContext(ctx, `INSERT INTO native_campaign_corpus_entries(task_id,manifest_id,ordinal,object_id,sha256,length,storage_key,source_type,source_ref)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, cmd.TaskID, manifestID, entry.Ordinal, entry.ObjectID, entry.SHA256, entry.Length, entry.StorageKey, entry.SourceType, entry.SourceRef); err != nil {
			return nil, err
		}
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `WITH c AS (INSERT INTO native_campaign_checkpoints(task_id,campaign_id,attempt_id,manifest_id,state,entry_count,total_bytes,truncated,verified_at)
  VALUES($1,$2,$3,$4,'verified',$5,$6,$7,clock_timestamp()) RETURNING *) SELECT row_to_json(c) FROM c`, cmd.TaskID, cmd.CampaignID, cmd.AttemptID, manifestID, in.EntryCount, in.TotalBytes, in.Truncated).Scan(&raw); err != nil {
		return nil, err
	}
	var out NativeCampaignCheckpoint
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &out, nil
}
