package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Emulates only restore's final transactional provenance step. This is not a
// package restore test; the actual restore will hold the same task exclusion.
func markCampaignRestoredForTest(t *testing.T, d *DB, taskID, campaignID int64) {
	t.Helper()
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, taskID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE native_campaigns SET desired_state='none' WHERE task_id=$1 AND id=$2`, taskID, campaignID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO native_campaign_events(task_id,campaign_id,kind,payload) VALUES($1,$2,'campaign.archive_restored','{}')`, taskID, campaignID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}
func TestNativeCampaignRestoredGateBeforeReplayAndClaim(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "restored-replay")
	c := t3CreateDraft(t, d, task, artifact, "restored-replay")
	version := c.StateVersion
	request := t3ReqID("restored-replay")
	c = t3Start(t, d, c, version, request, nil)
	markCampaignRestoredForTest(t, d, task.ID, c.ID)
	for _, action := range []string{"start", "resume"} {
		cmd := NativeCampaignStateCommand{TaskID: task.ID, CampaignID: c.ID, ExpectedStateVersion: version, RequestID: request}
		if action == "start" {
			_, err = d.StartNativeCampaign(context.Background(), t3AllowAuth, cmd)
		} else {
			cmd.RequestID = t3ReqID("restored-resume")
			_, err = d.ResumeNativeCampaign(context.Background(), t3AllowAuth, cmd)
		}
		if NativeCampaignErrorCode(err) != "archive_restore_not_executable" {
			t.Fatalf("%s accepted restored record: %v", action, err)
		}
	}
	if _, err = t3Claim(t, d, task, c, "restored-claim", nil); NativeCampaignErrorCode(err) != "archive_restore_not_executable" {
		t.Fatalf("restored claim: %v", err)
	}
	_, run := newNativeCampaignRun(t, d, task, artifact, "failed")
	if _, err = d.CreateNativeCampaignAttempt(context.Background(), NativeCampaignAttemptInput{TaskID: task.ID, CampaignID: c.ID, AttemptNo: 1, NativeRunID: run, RuntimeRunID: run, LeaseInstance: "restored", LeaseExpiresAt: time.Now().Add(time.Minute), ReservedBudgetMS: 60000}); NativeCampaignErrorCode(err) != "archive_restore_not_executable" {
		t.Fatalf("low-level restored attempt: %v", err)
	}
	v, err := d.ValidateNativeCampaign(context.Background(), task.ID, c.ID)
	if err != nil || v.CanStart || v.CanResume || v.Checks["archive"].OK {
		t.Fatalf("restored validation=%+v err=%v", v, err)
	}
	var n int
	if err = d.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE campaign_id=$1`, c.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("restored gate created an attempt")
	}
	if _, err = d.CreateNativeCampaignEvent(context.Background(), NativeCampaignEventInput{TaskID: task.ID, CampaignID: c.ID, Kind: nativeCampaignArchiveRestoredEvent, Payload: []byte(`{}`)}); err == nil {
		t.Fatal("ordinary writer forged reserved provenance")
	}
	mustNativeCampaignSQLFail(t, d, `DELETE FROM native_campaign_events WHERE campaign_id=$1 AND kind='campaign.archive_restored'`, c.ID)
}
func TestNativeCampaignRestoredGateRejectsLateOwners(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _, c, a, _, _ := campaignPausedPointerFixture(t, d)
	id := nativeCampaignLeaseIdentityOf(a)
	evidenceInput := NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/restore-test.json", task.ID), SHA256: nativeCampaignHash("restore-evidence"), Observation: []byte(`{}`)}
	evidence, err := d.CreateNativeCampaignEvidence(context.Background(), evidenceInput)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := json.Marshal(map[string]any{"version": 1, "task_id": task.ID, "campaign_id": c.ID, "attempt_id": a.ID, "fencing_token": id.FencingToken, "plan_sha256": nativeCampaignHash("restore-plan")})
	manifest := NativeCampaignManifestInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, ManifestSHA256: nativeCampaignHash("restore-manifest"), EntryCount: 1, TotalBytes: 1, Entries: []NativeCampaignEntryInput{{Ordinal: 0, SHA256: nativeCampaignHash("restore-object"), Length: 1, SourceType: "seed", SourceRef: "seed.bin"}}}
	markCampaignRestoredForTest(t, d, task.ID, c.ID)
	calls := []struct {
		name string
		call func() error
	}{
		{"renew", func() error {
			_, e := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{NativeCampaignLeaseIdentity: id, LeaseMS: 30000})
			return e
		}},
		{"check_start", func() error { _, e := d.CheckNativeCampaignAttemptStart(context.Background(), id); return e }},
		{"mark_started", func() error {
			_, e := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{NativeCampaignLeaseIdentity: id, Phase: "startup", OwnedResources: []byte(`{}`)})
			return e
		}},
		{"halt", func() error {
			_, e := d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{NativeCampaignLeaseIdentity: id, Reason: "late"})
			return e
		}},
		{"cleanup_snapshot", func() error {
			_, e := d.NativeCampaignCleanupSnapshot(context.Background(), t3AllowAuth, task.ID, c.ID, a.ID)
			return e
		}},
		{"cleanup_retry", func() error {
			_, e := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, CleanupVerified: true, ActorKind: "admin"})
			return e
		}},
	}
	calls = append(calls,
		struct {
			name string
			call func() error
		}{"finalize", func() error {
			_, e := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignFinalizeCommand{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, FencingToken: id.FencingToken, LeaseOwner: id.LeaseOwner, LeaseInstance: id.LeaseInstance, TargetState: "failed", EvidenceID: evidence.ID, CleanupStatus: "verified", TerminationReason: "late", ActorKind: "admin"})
			return e
		}},
		struct {
			name string
			call func() error
		}{"checkpoint", func() error {
			_, e := d.CommitVerifiedNativeCampaignCheckpoint(context.Background(), NativeCampaignCheckpointCommit{NativeCampaignLeaseIdentity: id, Manifest: manifest})
			return e
		}},
		struct {
			name string
			call func() error
		}{"seal", func() error {
			_, e := d.SealNativeCampaignAttemptCreation(context.Background(), t3AllowAuth, id, []byte(`{"resource_plan":{}}`), proof)
			return e
		}},
		struct {
			name string
			call func() error
		}{"fenced_evidence", func() error {
			_, e := d.PrepareNativeCampaignFinalEvidence(context.Background(), id, evidenceInput)
			return e
		}},
	)
	for _, tc := range calls {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); NativeCampaignErrorCode(err) != "archive_restore_not_executable" {
				t.Fatalf("late operation error=%v", err)
			}
		})
	}
	got := t3ReloadCampaign(t, d, c)
	attempt := t3ReloadAttempt(t, d, a)
	if got.State != "paused" || got.DesiredState != "none" || attempt.State != "paused" || attempt.ResourceHold {
		t.Fatal("late operation altered restored history")
	}
}

func TestNativeCampaignWaitingReplaySeesRestoreCommit(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "restore-waiter")
	c := t3CreateDraft(t, d, task, artifact, "restore-waiter")
	version := c.StateVersion
	request := t3ReqID("restore-waiter")
	c = t3Start(t, d, c, version, request, nil)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	launched := false
	defer func() {
		cancel()
		_ = tx.Rollback()
		if launched {
			<-done
		}
	}()
	var blocker int
	if err = tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE native_campaigns SET desired_state='none' WHERE id=$1`, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO native_campaign_events(task_id,campaign_id,kind,payload) VALUES($1,$2,'campaign.archive_restored','{}')`, task.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	launched = true
	go func() {
		_, e := d.StartNativeCampaign(ctx, t3AllowAuth, NativeCampaignStateCommand{TaskID: task.ID, CampaignID: c.ID, ExpectedStateVersion: version, RequestID: request})
		done <- e
	}()
	until := time.Now().Add(2 * time.Second)
	for {
		var blocked bool
		if err = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(until) {
			t.Fatal("replay did not wait on restore task lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	err = <-done
	launched = false
	if NativeCampaignErrorCode(err) != "archive_restore_not_executable" || ctx.Err() != nil {
		t.Fatalf("same replay waiter returned %v", err)
	}
	var n int
	if err = d.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE campaign_id=$1`, c.ID).Scan(&n); err != nil || n != 0 {
		t.Fatal("waiting replay created execution")
	}
}

func TestNativeCampaignCompactionTransactionIDCompatibility(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var top, child, next int64
	var typ, version string
	if err = tx.QueryRow(`SELECT txid_current(),pg_typeof(txid_current())::text,current_setting('server_version')`).Scan(&top, &typ, &version); err != nil {
		t.Fatal(err)
	}
	if typ != "bigint" || top <= 0 {
		t.Fatalf("unexpected transaction ID %d %s", top, typ)
	}
	if _, err = tx.Exec(`CREATE TEMP TABLE artex_compaction_txid_probe(n integer) ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`SAVEPOINT child_write`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO artex_compaction_txid_probe VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	if err = tx.QueryRow(`SELECT txid_current()`).Scan(&child); err != nil || child != top {
		t.Fatalf("subtransaction changed top ID: %d %d %v", top, child, err)
	}
	if _, err = tx.Exec(`ROLLBACK TO SAVEPOINT child_write`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx2, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Rollback()
	if err = tx2.QueryRow(`SELECT txid_current()`).Scan(&next); err != nil || next == top {
		t.Fatalf("next transaction reused identity: %d %d %v", top, next, err)
	}
	t.Logf("actual PostgreSQL %s: bigint expanded txid stable across child write, distinct after commit", version)
}
