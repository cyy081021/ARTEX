package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestNativeCampaignMetadataArchiveAdmission(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, state := range []string{"archive_queued", "archiving", "ready", "archive_failed", "deleted"} {
		t.Run(state, func(t *testing.T) {
			task, _ := newNativeCampaignTask(t, d, "metadata-admission-"+state)
			if state == "deleted" {
				_, err = d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, task.ID)
			} else {
				_, err = d.Exec(`INSERT INTO task_archives(task_id,state) VALUES($1,$2)`, task.ID, state)
			}
			if err != nil {
				t.Fatal(err)
			}
			_, oe := d.CreateNativeCampaignObject(context.Background(), NativeCampaignObjectInput{TaskID: task.ID, SHA256: nativeCampaignHash(state), Length: 1})
			_, re := d.CreateNativeCampaignRequest(context.Background(), NativeCampaignRequestInput{TaskID: task.ID, RequestID: "nullable-campaign", Action: "create", RequestHash: nativeCampaignHash(state), ResponseStatus: 200, ResponseBody: []byte(`{}`)})
			if state == "archive_failed" {
				if oe != nil || re != nil {
					t.Fatalf("failed archive blocked hot task: %v %v", oe, re)
				}
			} else {
				if oe == nil || re == nil {
					t.Fatalf("frozen task accepted write: %v %v", oe, re)
				}
				var n int
				if err := d.QueryRow(`SELECT (SELECT count(*) FROM native_campaign_objects WHERE task_id=$1)+(SELECT count(*) FROM native_campaign_requests WHERE task_id=$1)`, task.ID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("partial write n=%d err=%v", n, err)
				}
			}
		})
	}
}

func TestNativeCampaignMetadataWaitsForTaskAdmission(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _ := newNativeCampaignTask(t, d, "metadata-admission-lock")
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`SELECT id FROM tasks WHERE id=$1 FOR UPDATE`, task.ID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err = d.CreateNativeCampaignObject(ctx, NativeCampaignObjectInput{TaskID: task.ID, SHA256: nativeCampaignHash("lock"), Length: 1}); err == nil || ctx.Err() == nil {
		t.Fatalf("writer bypassed task admission: %v", err)
	}
	if _, err = tx.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateNativeCampaignObject(context.Background(), NativeCampaignObjectInput{TaskID: task.ID, SHA256: nativeCampaignHash("lock"), Length: 1}); err == nil {
		t.Fatal("late writer accepted archived stub")
	}
}

func TestNativeCampaignSameWaitingWriterRechecksArchived(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, kind := range []string{"object", "nullable_request"} {
		t.Run(kind, func(t *testing.T) {
			task, _ := newNativeCampaignTask(t, d, "metadata-admission-wait-"+kind)
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
			launched = true
			go func() {
				if kind == "object" {
					_, e := d.CreateNativeCampaignObject(ctx, NativeCampaignObjectInput{TaskID: task.ID, SHA256: nativeCampaignHash(kind), Length: 1})
					done <- e
				} else {
					_, e := d.CreateNativeCampaignRequest(ctx, NativeCampaignRequestInput{TaskID: task.ID, RequestID: "same-waiter", Action: "create", RequestHash: nativeCampaignHash(kind), ResponseStatus: 200, ResponseBody: []byte(`{}`)})
					done <- e
				}
			}()
			waitUntil := time.Now().Add(2 * time.Second)
			for {
				var blocked bool
				if err = d.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1::integer=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				if time.Now().After(waitUntil) {
					t.Fatal("writer never waited on exact blocker")
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err = tx.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, task.ID); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			err = <-done
			launched = false
			if err == nil || ctx.Err() != nil {
				t.Fatalf("same waiter did not reject archived task before timeout: %v", err)
			}
			var n int
			if err = d.QueryRow(`SELECT (SELECT count(*) FROM native_campaign_objects WHERE task_id=$1)+(SELECT count(*) FROM native_campaign_requests WHERE task_id=$1)`, task.ID).Scan(&n); err != nil || n != 0 {
				t.Fatalf("late writer left rows=%d err=%v", n, err)
			}
		})
	}
}

func TestNativeCampaignDeletedTaskOwnedSettlement(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "deleted-owned-settlement")
	campaign := t3CreateDraft(t, d, task, artifact, "deleted-owned-settlement")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("deleted-start"), nil)
	attempt := t3MustClaim(t, d, task, campaign, "deleted-owned-instance").Attempt
	id := nativeCampaignLeaseIdentityOf(attempt)
	if _, err = d.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchive(task.ID); err == nil {
		t.Fatal("archive admitted active held attempt")
	}
	if _, err = d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{NativeCampaignLeaseIdentity: id, LeaseMS: 30000}); err == nil {
		t.Fatal("deleted task renewed execution")
	}
	if _, err = d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{NativeCampaignLeaseIdentity: id, Phase: "startup", OwnedResources: []byte(`{}`)}); err == nil {
		t.Fatal("deleted task started")
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err = d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{TaskID: task.ID, CampaignID: campaign.ID, ExpectedStateVersion: campaign.StateVersion, RequestID: t3ReqID("deleted-cancel")}); err != nil {
		t.Fatalf("deleted task cannot request cancellation: %v", err)
	}
	in := NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID, Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/final.json", task.ID), SHA256: nativeCampaignHash("deleted-final"), Observation: []byte(`{}`)}
	if _, err = d.CreateNativeCampaignEvidence(context.Background(), in); err == nil {
		t.Fatal("ordinary metadata accepted deleted task")
	}
	wrong := id
	wrong.FencingToken++
	if _, err = d.PrepareNativeCampaignFinalEvidence(context.Background(), wrong, in); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("stale evidence fence accepted: %v", err)
	}
	ev, err := d.PrepareNativeCampaignFinalEvidence(context.Background(), id, in)
	if err != nil {
		t.Fatalf("owned final evidence blocked: %v", err)
	}
	if _, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignFinalizeCommand{TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID, FencingToken: id.FencingToken, LeaseOwner: id.LeaseOwner, LeaseInstance: id.LeaseInstance, TargetState: "cancelled", Phase: "finalize", CleanupStatus: "verified", EvidenceID: ev.ID, TerminationReason: "user_cancel", ActorKind: "admin"}); err != nil {
		t.Fatalf("owned cancellation blocked: %v", err)
	}
	if got := t3ReloadAttempt(t, d, attempt); got.ResourceHold || got.State != "cancelled" {
		t.Fatalf("settlement not complete: %+v", got)
	}
}

func TestNativeCampaignArchiveAdmissionBeforeReplay(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "archive-before-replay")
	c := t3CreateDraft(t, d, task, artifact, "archive-before-replay")
	version := c.StateVersion
	request := t3ReqID("archive-before-replay-start")
	c = t3Start(t, d, c, version, request, nil)
	if _, err = d.Exec(`INSERT INTO task_archives(task_id,state) VALUES($1,'archive_queued')`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{TaskID: task.ID, CampaignID: c.ID, ExpectedStateVersion: version, RequestID: request}); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("archiving returned prior start permission: %v", err)
	}
	if _, err = t3Claim(t, d, task, c, "archive-blocked-claim", nil); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("archiving claim accepted: %v", err)
	}
}
