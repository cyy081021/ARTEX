package db

import (
	"context"
	"database/sql"
	"errors"
)

type nativeCampaignWritePurpose uint8

const (
	nativeCampaignNewWrite nativeCampaignWritePurpose = iota
	nativeCampaignOwnedSettlement
)

// admitNativeCampaignWriteTx is always the first row/advisory lock in a
// Campaign writer transaction. Callers retain it through commit. Settlement
// callers still must validate their original attempt ownership/fence afterward.
// No public input selects the settlement purpose; archive restore has its own
// transaction and does not call this ordinary-writer admission function.
func admitNativeCampaignWriteTx(ctx context.Context, tx *sql.Tx, taskID int64, purpose nativeCampaignWritePurpose) error {
	var deleted, archived bool
	err := tx.QueryRowContext(ctx, `SELECT deleted_at IS NOT NULL, archived_at IS NOT NULL
 FROM tasks WHERE id=$1 FOR SHARE`, taskID).Scan(&deleted, &archived)
	if errors.Is(err, sql.ErrNoRows) {
		return nativeCampaignNotFound("task")
	}
	if err != nil {
		return err
	}
	if purpose != nativeCampaignNewWrite && purpose != nativeCampaignOwnedSettlement {
		return nativeCampaignErrorf("internal", 500, "invalid writer purpose")
	}
	if deleted && purpose == nativeCampaignNewWrite {
		return nativeCampaignNotFound("task")
	}
	if archived {
		return nativeCampaignErrorf("state_conflict", 409, "task is archived")
	}
	var frozen bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM task_archives WHERE task_id=$1 AND state<>'archive_failed')`, taskID).Scan(&frozen); err != nil {
		return err
	}
	if frozen {
		return nativeCampaignErrorf("state_conflict", 409, "task archive is in progress")
	}
	return nil
}

const nativeCampaignArchiveRestoredEvent = "campaign.archive_restored"

// NativeCampaignArchiveRestored is a read-only diagnostic. Mutations repeat the
// check under task admission; a preflight read is never execution permission.
func (d *DB) NativeCampaignArchiveRestored(ctx context.Context, taskID, campaignID int64) (bool, error) {
	var restored bool
	err := d.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM native_campaign_events WHERE task_id=$1 AND campaign_id=$2 AND kind=$3)`, taskID, campaignID, nativeCampaignArchiveRestoredEvent).Scan(&restored)
	return restored, err
}
func rejectNativeCampaignArchiveRestoredTx(ctx context.Context, tx *sql.Tx, taskID, campaignID int64) error {
	var restored bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM native_campaign_events WHERE task_id=$1 AND campaign_id=$2 AND kind=$3)`, taskID, campaignID, nativeCampaignArchiveRestoredEvent).Scan(&restored); err != nil {
		return err
	}
	if restored {
		return nativeCampaignErrorf("archive_restore_not_executable", 409, "restored campaign is not executable")
	}
	return nil
}
