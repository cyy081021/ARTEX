package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const nativeCampaignPointerChecks = "native_campaigns_pointer_targets_check, native_campaign_attempt_pointer_targets_check"

func campaignPausedPointerFixture(t *testing.T, d *DB) (*Task, *ReverseArtifact, *NativeCampaign, *NativeCampaignAttempt, *NativeCampaignCorpusManifest, *NativeCampaignCheckpoint) {
	t.Helper()
	task, artifact := newNativeCampaignTask(t, d, "paused-pointer-restore")
	c := newNativeCampaign(t, d, task, artifact, "paused-pointer-restore")
	_, run := newNativeCampaignRun(t, d, task, artifact, "paused")
	a := newNativeCampaignAttempt(t, d, task, c, run, 1)
	o := newNativeCampaignObject(t, d, task, "paused-pointer-object", 8)
	m := newNativeCampaignManifest(t, d, task, c, a, o, "paused-pointer")
	cp := newNativeCampaignCheckpoint(t, d, task, c, a, m)
	verifyNativeCampaignCheckpoint(t, d, cp)
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET checkpoint_id=$2,state='paused',cleanup_status='verified',resource_hold=false,hold_reason=NULL WHERE id=$1`, a.ID, cp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE native_campaigns SET state='paused',desired_state='none',current_attempt_id=$2,latest_checkpoint_id=$3,cleanup_status='verified',pause_origin='running' WHERE id=$1`, c.ID, a.ID, cp.ID); err != nil {
		t.Fatal(err)
	}
	return task, artifact, c, a, m, cp
}

func TestNativeCampaignDeferredPausedPointerGraph(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact, c, a, m, cp := campaignPausedPointerFixture(t, d)
	source := map[string]int64{"native_campaigns": c.ID, "native_campaign_attempts": a.ID, "native_campaign_corpus_manifests": m.ID, "native_campaign_checkpoints": cp.ID}
	base := map[string]map[string]any{}
	for table, id := range source {
		var raw []byte
		if err := d.QueryRow(`SELECT row_to_json(x) FROM `+table+` x WHERE id=$1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		rows, err := decodeArchiveRows(append(append([]byte{'['}, raw...), ']'))
		if err != nil {
			t.Fatal(err)
		}
		base[table] = rows[0]
	}
	var entriesRaw []byte
	if err := d.QueryRow(`SELECT json_agg(e) FROM native_campaign_corpus_entries e WHERE manifest_id=$1`, m.ID).Scan(&entriesRaw); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"immediate_reject", "deferred_paused", "deferred_bad_target", "deferred_bad_commit"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if mode != "immediate_reject" {
				if _, err = tx.Exec(`SET CONSTRAINTS ` + nativeCampaignPointerChecks + ` DEFERRED`); err != nil {
					t.Fatal(err)
				}
			}
			ids := map[string]int64{}
			rows := map[string]map[string]any{}
			for table, row := range base {
				var id int64
				if err = tx.QueryRow(`SELECT nextval(pg_get_serial_sequence($1,'id'))`, table).Scan(&id); err != nil {
					t.Fatal(err)
				}
				ids[table] = id
				raw, _ := json.Marshal(row)
				copyRows, _ := decodeArchiveRows(append(append([]byte{'['}, raw...), ']'))
				rows[table] = copyRows[0]
				rows[table]["id"] = id
			}
			cid, aid, mid, cpid := ids["native_campaigns"], ids["native_campaign_attempts"], ids["native_campaign_corpus_manifests"], ids["native_campaign_checkpoints"]
			rows["native_campaigns"]["current_attempt_id"] = aid
			rows["native_campaigns"]["latest_checkpoint_id"] = cpid
			for _, table := range []string{"native_campaign_attempts", "native_campaign_corpus_manifests", "native_campaign_checkpoints"} {
				rows[table]["campaign_id"] = cid
			}
			rows["native_campaign_attempts"]["checkpoint_id"] = cpid
			for _, table := range []string{"native_campaign_corpus_manifests", "native_campaign_checkpoints"} {
				rows[table]["attempt_id"] = aid
			}
			rows["native_campaign_checkpoints"]["manifest_id"] = mid
			if mode == "deferred_bad_target" || mode == "deferred_bad_commit" {
				rows["native_campaigns"]["latest_checkpoint_id"] = cp.ID
			} // valid FK, wrong campaign
			insert := func(table string, row map[string]any) error {
				raw, _ := json.Marshal(row)
				_, e := tx.Exec(`INSERT INTO `+table+` SELECT * FROM json_populate_record(NULL::`+table+`,$1::json)`, string(raw))
				return e
			}
			err = insert("native_campaigns", rows["native_campaigns"])
			if mode == "immediate_reject" {
				if err == nil {
					t.Fatal("ordinary insert accepted missing targets")
				}
				return
			}
			if err != nil {
				t.Fatalf("paused original-state insert failed: %v", err)
			}
			// Distinct actual run rows, no active runner. Clone preserves paused state.
			var rid int64
			if err = tx.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,profile_id,status) VALUES($1,$2,'pointer-restore','paused') RETURNING id`, task.ID, artifact.ID).Scan(&rid); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation) VALUES($1,$2,$3,0,1,'campaign','paused','{}')`, rid, task.ID, artifact.ID); err != nil {
				t.Fatal(err)
			}
			rows["native_campaign_attempts"]["native_run_id"] = rid
			rows["native_campaign_attempts"]["runtime_run_id"] = rid
			if err = insert("native_campaign_attempts", rows["native_campaign_attempts"]); err != nil {
				t.Fatal(err)
			}
			var sourceEntries []NativeCampaignCorpusEntry
			if err = json.Unmarshal(entriesRaw, &sourceEntries); err != nil {
				t.Fatal(err)
			}
			canonicalEntries := make([]NativeCampaignEntryInput, len(sourceEntries))
			for i, e := range sourceEntries {
				canonicalEntries[i] = NativeCampaignEntryInput{Ordinal: e.Ordinal, ObjectID: e.ObjectID, SHA256: e.SHA256, Length: e.Length, StorageKey: e.StorageKey, SourceType: e.SourceType, SourceRef: e.SourceRef}
			}
			canonical, err := CanonicalNativeCampaignManifest(cid, aid, canonicalEntries)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(canonical)
			rows["native_campaign_corpus_manifests"]["manifest_sha256"] = hex.EncodeToString(digest[:])
			if err = insert("native_campaign_corpus_manifests", rows["native_campaign_corpus_manifests"]); err != nil {
				t.Fatal(err)
			}
			entries, _ := decodeArchiveRows(entriesRaw)
			for _, entry := range entries {
				var eid int64
				if err = tx.QueryRow(`SELECT nextval(pg_get_serial_sequence('native_campaign_corpus_entries','id'))`).Scan(&eid); err != nil {
					t.Fatal(err)
				}
				entry["id"] = eid
				entry["manifest_id"] = mid
				if err = insert("native_campaign_corpus_entries", entry); err != nil {
					t.Fatal(err)
				}
			}
			if err = insert("native_campaign_checkpoints", rows["native_campaign_checkpoints"]); err != nil {
				t.Fatal(err)
			}
			if mode == "deferred_bad_commit" {
				err = tx.Commit()
				if err == nil {
					t.Fatal("invalid deferred graph committed without explicit check")
				}
				var n int
				if err = d.QueryRow(`SELECT count(*) FROM native_campaigns WHERE id=$1`, cid).Scan(&n); err != nil || n != 0 {
					t.Fatal("automatic constraint failure did not roll back")
				}
				return
			}
			_, err = tx.Exec(`SET CONSTRAINTS ` + nativeCampaignPointerChecks + ` IMMEDIATE`)
			if mode == "deferred_bad_target" {
				if err == nil {
					t.Fatal("deferred foreign checkpoint accepted")
				}
				_ = tx.Rollback()
				var n int
				if err = d.QueryRow(`SELECT count(*) FROM native_campaigns WHERE id=$1`, cid).Scan(&n); err != nil || n != 0 {
					t.Fatal("failed graph did not roll back")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			got, err := d.NativeCampaign(context.Background(), task.ID, cid)
			if err != nil || got.State != "paused" || got.DesiredState != "none" || got.CurrentAttemptID == nil || *got.CurrentAttemptID != aid || got.LatestCheckpointID == nil || *got.LatestCheckpointID != cpid {
				t.Fatalf("paused graph not preserved: %+v %v", got, err)
			}
		})
	}
}

func TestNativeCampaignDeferredTargetsKeepImmediateImmutability(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	_, _, c, a, _, _ := campaignPausedPointerFixture(t, d)
	for _, q := range []string{fmt.Sprintf("UPDATE native_campaigns SET latest_checkpoint_id=NULL WHERE id=%d", c.ID), fmt.Sprintf("UPDATE native_campaigns SET current_attempt_id=NULL WHERE id=%d", c.ID), fmt.Sprintf("UPDATE native_campaign_attempts SET checkpoint_id=checkpoint_id+1 WHERE id=%d", a.ID)} {
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = tx.Exec(`SET CONSTRAINTS ` + nativeCampaignPointerChecks + ` DEFERRED`); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		_, err = tx.Exec(q)
		_ = tx.Rollback()
		if err == nil || (!strings.Contains(err.Error(), "cannot be cleared") && !strings.Contains(err.Error(), "immutable once set")) {
			t.Fatalf("deferred targets weakened transition rule: %v", err)
		}
	}
}

func TestNativeCampaignDeferredPointerReadsFinalRow(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact, c, a, _, _ := campaignPausedPointerFixture(t, d)
	_, run := newNativeCampaignRun(t, d, task, artifact, "failed")
	temporary := newNativeCampaignAttempt(t, d, task, c, run, 2)
	if _, err = d.Exec(`UPDATE native_campaign_attempts SET state='failed',cleanup_status='verified',resource_hold=false,hold_reason=NULL WHERE id=$1`, temporary.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SET CONSTRAINTS ` + nativeCampaignPointerChecks + ` DEFERRED`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE native_campaigns SET current_attempt_id=$2 WHERE id=$1`, c.ID, temporary.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE native_campaigns SET current_attempt_id=$2 WHERE id=$1`, c.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`DELETE FROM native_campaign_attempts WHERE id=$1`, temporary.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatalf("stale NEW version was validated instead of final row: %v", err)
	}
	got, err := d.NativeCampaign(context.Background(), task.ID, c.ID)
	if err != nil || got.CurrentAttemptID == nil || *got.CurrentAttemptID != a.ID || got.State != "paused" {
		t.Fatalf("final pointer changed: %+v %v", got, err)
	}
}
