package db

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Resolve without locking, then use the common task -> archive order. Recheck
// identity after both locks; never rely on a joined query's execution plan.
func lockTaskArchiveIdentityTx(tx *sql.Tx, archiveID int64) (taskID, expID int64, state string, err error) {
	if err = tx.QueryRow(`SELECT task_id FROM task_archives WHERE id=$1`, archiveID).Scan(&taskID); err != nil {
		return
	}
	if err = tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 FOR UPDATE`, taskID).Scan(&expID); err != nil {
		return
	}
	var lockedTask int64
	if err = tx.QueryRow(`SELECT task_id,state FROM task_archives WHERE id=$1 FOR UPDATE`, archiveID).Scan(&lockedTask, &state); err != nil {
		return
	}
	if lockedTask != taskID {
		err = fmt.Errorf("%w: archive task changed", ErrTaskArchiveState)
	}
	return
}

func lockQuiescentNativeCampaignsTx(tx *sql.Tx, taskID int64) error {
	for _, table := range []string{"native_campaigns", "native_campaign_attempts"} {
		rows, err := tx.Query(`SELECT id FROM `+table+` WHERE task_id=$1 ORDER BY id FOR UPDATE`, taskID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	var busy bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM native_campaign_attempts WHERE task_id=$1 AND (resource_hold OR state IN ('claimed','launching','running','stopping','collecting','cleaning')))
 OR EXISTS(SELECT 1 FROM native_campaigns WHERE task_id=$1 AND state IN ('running','stopping'))`, taskID).Scan(&busy); err != nil {
		return err
	}
	if busy {
		return fmt.Errorf("%w: campaign resources are not settled", ErrTaskArchiveIneligible)
	}
	return nil
}

// Stable row order plus UseNumber decoding compare complete table contents,
// including history/prepared rows. This rejects a stale package from an earlier
// failed/retried archive cycle. It is separate from task admission and file hash
// verification, not a substitute for either.
func compareNativeCampaignArchiveSnapshotTx(tx *sql.Tx, snapshot *TaskArchiveSnapshot) error {
	for _, table := range nativeCampaignArchiveTables {
		current, _, err := queryArchiveRows(tx, `SELECT * FROM `+table+` WHERE task_id=$1 ORDER BY id`, snapshot.TaskID)
		if err != nil {
			return err
		}
		before, err := decodeArchiveRows(snapshot.Tables[table])
		if err != nil {
			return err
		}
		after, err := decodeArchiveRows(current)
		if err != nil {
			return err
		}
		left, err := json.Marshal(before)
		if err != nil {
			return err
		}
		right, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if !bytes.Equal(left, right) {
			return fmt.Errorf("%w: Campaign snapshot changed", ErrTaskArchiveState)
		}
	}
	return nil
}

func compactNativeCampaignArchiveTx(tx *sql.Tx, archiveID int64, snapshot *TaskArchiveSnapshot) error {
	if err := lockQuiescentNativeCampaignsTx(tx, snapshot.TaskID); err != nil {
		return err
	}
	if err := compareNativeCampaignArchiveSnapshotTx(tx, snapshot); err != nil {
		return err
	}
	result, err := tx.Exec(`UPDATE task_archives SET phase='database_compacting',format_version=6,compaction_txid=txid_current() WHERE id=$1 AND task_id=$2 AND state='archiving'`, archiveID, snapshot.TaskID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return ErrTaskArchiveState
	}
	for _, table := range []string{"native_campaign_events", "native_campaign_evidence", "native_campaign_checkpoints", "native_campaign_corpus_entries", "native_campaign_corpus_manifests", "native_campaign_objects", "native_campaign_requests", "native_campaign_attempts", "native_campaigns"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE task_id=$1`, snapshot.TaskID); err != nil {
			return err
		}
	}
	return nil
}

func restoreNativeCampaignArchiveTx(tx *sql.Tx, snapshot *TaskArchiveSnapshot) error {
	if snapshot.FormatVersion < 6 {
		return nil
	}
	if _, err := tx.Exec(`SET CONSTRAINTS native_campaigns_pointer_targets_check,native_campaign_attempt_pointer_targets_check,native_campaigns_current_attempt_fk,native_campaigns_latest_checkpoint_fk,native_campaign_attempts_checkpoint_fk,native_campaign_attempts_evidence_fk DEFERRED`); err != nil {
		return err
	}
	for _, table := range []string{"native_campaigns", "native_campaign_attempts", "native_campaign_objects", "native_campaign_corpus_manifests", "native_campaign_corpus_entries", "native_campaign_checkpoints", "native_campaign_evidence", "native_campaign_requests", "native_campaign_events"} {
		raw := snapshot.Tables[table]
		if table == "native_campaigns" {
			rows, err := decodeArchiveRows(raw)
			if err != nil {
				return err
			}
			for _, row := range rows {
				row["desired_state"] = "none"
			}
			raw, err = json.Marshal(rows)
			if err != nil {
				return err
			}
		}
		if err := insertArchiveRows(tx, table, raw); err != nil {
			return err
		}
	}
	// Same-database stub restore preserves existing sequences. Do not reset global
	// sequences or import arbitrary cross-database high IDs. Appending provenance
	// uses the ordinary sequence, whose allocation survived hot-store compaction.
	if _, err := tx.Exec(`INSERT INTO native_campaign_events(task_id,campaign_id,kind,payload)
 SELECT task_id,id,'campaign.archive_restored','{}'::jsonb FROM native_campaigns WHERE task_id=$1 ORDER BY id`, snapshot.TaskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`SET CONSTRAINTS native_campaigns_pointer_targets_check,native_campaign_attempt_pointer_targets_check,native_campaigns_current_attempt_fk,native_campaigns_latest_checkpoint_fk,native_campaign_attempts_checkpoint_fk,native_campaign_attempts_evidence_fk IMMEDIATE`); err != nil {
		return err
	}
	return nil
}

// NativeCampaignArchiveFile is a task-relative immutable reference retained in
// the v6 graph. Length is exact for objects; evidence has a bounded envelope.
type NativeCampaignArchiveFile struct {
	Path     string
	SHA256   string
	Length   int64
	MaxBytes int64
}

func NativeCampaignArchiveFiles(snapshot *TaskArchiveSnapshot) ([]NativeCampaignArchiveFile, error) {
	if err := validateNativeCampaignArchiveScope(snapshot); err != nil {
		return nil, err
	}
	if snapshot.FormatVersion < 6 {
		return nil, nil
	}
	var out []NativeCampaignArchiveFile
	for _, table := range []string{"native_campaign_objects", "native_campaign_evidence"} {
		rows, err := decodeArchiveRows(snapshot.Tables[table])
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			ref := NativeCampaignArchiveFile{SHA256: r["sha256"].(string)}
			if table == "native_campaign_objects" {
				ref.Path = r["storage_key"].(string)
				ref.Length, _ = jsonInt64(r["length"])
				ref.MaxBytes = 4096
			} else {
				ref.Path = r["result_path"].(string)
				ref.MaxBytes = 512 << 10
			}
			out = append(out, ref)
		}
	}
	return out, nil
}
