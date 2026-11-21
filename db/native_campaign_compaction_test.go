package db

import (
	"context"
	"fmt"
	"testing"
)

func TestNativeCampaignCompactionTransactionGate(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, mode := range []string{"same_transaction", "phase_only", "stale_transaction", "wrong_task", "resource_hold", "legacy_version"} {
		t.Run(mode, func(t *testing.T) {
			task, _, c, a, _, cp := campaignPausedPointerFixture(t, d)
			ev, err := d.CreateNativeCampaignEvidence(context.Background(), NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, Kind: "pause", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/pause.json", task.ID), SHA256: nativeCampaignHash(mode), Observation: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			event, err := d.CreateNativeCampaignEvent(context.Background(), NativeCampaignEventInput{TaskID: task.ID, CampaignID: c.ID, Kind: "test.compaction", Payload: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			ownerTask := task.ID
			if mode == "wrong_task" {
				other, _ := newNativeCampaignTask(t, d, "other-compaction-task")
				ownerTask = other.ID
			}
			if mode == "resource_hold" {
				if _, err = d.Exec(`UPDATE native_campaign_attempts SET state='failed',cleanup_status='unknown',resource_hold=true,hold_reason='cleanup_unknown' WHERE id=$1`, a.ID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "stale_transaction" {
				if _, err = d.Exec(`INSERT INTO task_archives(task_id,state,phase,format_version,compaction_txid) VALUES($1,'archiving','database_compacting',6,txid_current())`, ownerTask); err != nil {
					t.Fatal(err)
				}
			}
			tx, err := d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, task.ID); err != nil {
				t.Fatal(err)
			}
			if mode != "stale_transaction" {
				version := 6
				if mode == "legacy_version" {
					version = 5
				}
				if _, err = tx.Exec(`INSERT INTO task_archives(task_id,state,phase,format_version,compaction_txid) VALUES($1,'archiving','database_compacting',$2,CASE WHEN $3::boolean THEN NULL ELSE txid_current() END)`, ownerTask, version, mode == "phase_only"); err != nil {
					t.Fatal(err)
				}
			}
			var allowed bool
			if err = tx.QueryRow(`SELECT native_campaign_compaction_authorized($1)`, task.ID).Scan(&allowed); err != nil {
				t.Fatal(err)
			}
			if allowed != (mode == "same_transaction") {
				t.Fatalf("authorization=%v mode=%s", allowed, mode)
			}
			// Use savepoints so every immutable guard is exercised on the same proof.
			for _, q := range []string{
				fmt.Sprintf("DELETE FROM native_campaign_events WHERE id=%d", event.ID),
				fmt.Sprintf("DELETE FROM native_campaign_evidence WHERE id=%d", ev.ID),
				fmt.Sprintf("DELETE FROM native_campaign_checkpoints WHERE id=%d", cp.ID),
				fmt.Sprintf("DELETE FROM native_campaign_corpus_entries WHERE manifest_id=%d", cp.ManifestID),
			} {
				if _, err = tx.Exec(`SAVEPOINT guarded_delete`); err != nil {
					t.Fatal(err)
				}
				_, e := tx.Exec(q)
				if (e == nil) != (mode == "same_transaction") {
					t.Fatalf("guard mismatch mode=%s query=%s err=%v", mode, q, e)
				}
				if _, err = tx.Exec(`ROLLBACK TO SAVEPOINT guarded_delete`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = tx.Exec(`SAVEPOINT immutable_update`); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(`UPDATE native_campaign_events SET payload='{}' WHERE id=$1`, event.ID); err == nil {
				t.Fatal("compaction made UPDATE mutable")
			}
			if _, err = tx.Exec(`ROLLBACK TO SAVEPOINT immutable_update`); err != nil {
				t.Fatal(err)
			}
			if mode == "resource_hold" {
				if _, err = tx.Exec(`DELETE FROM native_campaign_attempts WHERE id=$1`, a.ID); err == nil {
					t.Fatal("compaction bypassed held attempt guard")
				}
			}
			_ = tx.Rollback()
			var n int
			if err = d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE id=$1`, event.ID).Scan(&n); err != nil || n != 1 {
				t.Fatal("rolled-back proof lost event")
			}
		})
	}
}

func TestNativeCampaignCompactionPhaseIsReserved(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _ := newNativeCampaignTask(t, d, "reserved-phase")
	var id int64
	if err = d.QueryRow(`INSERT INTO task_archives(task_id) VALUES($1) RETURNING id`, task.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err = d.UpdateTaskArchiveProgress(id, "database_compacting", 50); err == nil {
		t.Fatal("generic API entered reserved phase")
	}
	var phase string
	var clean bool
	if err = d.QueryRow(`SELECT phase,compaction_txid IS NULL FROM task_archives WHERE id=$1`, id).Scan(&phase, &clean); err != nil || phase != "queued" || !clean {
		t.Fatal("reserved phase rejection changed row")
	}
}
