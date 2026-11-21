package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
 "time"
 "errors"
)

func TestNativeCampaignAtomicFinalEvidence(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, mode := range []string{"success", "bad_fence", "both_inputs", "wrong_identity", "current_mismatch", "expired", "update_failure", "event_failure", "commit_failure"} {
		t.Run(mode, func(t *testing.T) {
			task, artifact := newNativeCampaignTask(t, d, "atomic-evidence-"+mode)
			c := t3CreateDraft(t, d, task, artifact, "atomic-evidence-"+mode)
			c = t3Start(t, d, c, c.StateVersion, t3ReqID("atomic-start"), nil)
			var prior *NativeCampaignAttempt
			if mode == "current_mismatch" {
				_, nativeID := newNativeCampaignRun(t, d, task, artifact, "failed")
				prior = newNativeCampaignAttempt(t, d, task, c, nativeID, 1)
				releaseNativeCampaignAttempt(t, d, prior, "failed", "verified")
			}
			a := t3MustClaim(t, d, task, c, "atomic-owner").Attempt
			c = t3ReloadCampaign(t, d, c)
			input := &NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/atomic.json", task.ID, c.ID), SHA256: nativeCampaignHash("atomic"), Observation: json.RawMessage(`{"authority":"candidate-only"}`)}
			cmd := NativeCampaignFinalizeCommand{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, FencingToken: a.FencingToken, LeaseOwner: a.LeaseOwner, LeaseInstance: a.LeaseInstance, TargetState: "failed", CleanupStatus: "unknown", EvidenceInput: input, TerminationReason: "atomic_fixture", ActorKind: "admin", ActualElapsedMS: 1000, CleanupReserveMS: 1000}
			var eventsBefore int
			if err = d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE task_id=$1`, task.ID).Scan(&eventsBefore); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "bad_fence":
				cmd.FencingToken++
			case "both_inputs":
				cmd.EvidenceID = 1
			case "wrong_identity":
				input.AttemptID++
			}
			if mode == "current_mismatch" {
				if _, err = d.Exec(`UPDATE native_campaigns SET current_attempt_id=$1 WHERE id=$2`, prior.ID, c.ID); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "expired" {
				if _, err = d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, a.ID); err != nil {
					t.Fatal(err)
				}
			}
			c = t3ReloadCampaign(t, d, c)
			a = t3ReloadAttempt(t, d, a)
			beforeCampaign, _ := json.Marshal(c)
			beforeAttempt, _ := json.Marshal(a)
			if strings.HasSuffix(mode, "failure") {
				name := fmt.Sprintf("audit_atomic_evidence_%d", task.ID)
				table, event, timing := "native_campaign_attempts", "UPDATE", "BEFORE"
				prefix := "CREATE TRIGGER "
				if mode == "event_failure" {
					table, event = "native_campaign_events", "INSERT"
				}
				if mode == "commit_failure" {
					prefix = "CREATE CONSTRAINT TRIGGER "
					timing = "AFTER"
				}
				deferrable := ""
				if mode == "commit_failure" {
					deferrable = " DEFERRABLE INITIALLY DEFERRED"
				}
				fn := fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.task_id=%d THEN IF NOT EXISTS(SELECT 1 FROM native_campaign_evidence WHERE task_id=%d) THEN RAISE EXCEPTION 'wrong injection stage'; END IF; RAISE EXCEPTION 'injected atomic evidence failure'; END IF; RETURN NEW; END $$`, name, task.ID, task.ID)
				if _, err = d.Exec(fn + "; " + prefix + name + " " + timing + " " + event + " ON " + table + deferrable + " FOR EACH ROW EXECUTE FUNCTION " + name + "()"); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_, _ = d.Exec("DROP TRIGGER IF EXISTS " + name + " ON " + table + "; DROP FUNCTION IF EXISTS " + name + "()")
				}()
			}
			result, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, cmd)
			if mode == "success" {
				if err != nil || result.Attempt.EvidenceManifestID == nil {
					t.Fatalf("atomic publication failed: %+v %v", result, err)
				}
				evidenceID := *result.Attempt.EvidenceManifestID
				charged := result.Campaign.ChargedBudgetMS
				input.SHA256 = nativeCampaignHash("different retry file")
				again, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, cmd)
				if err != nil || !again.AlreadyFinalized || again.Attempt.EvidenceManifestID == nil || *again.Attempt.EvidenceManifestID != evidenceID || again.Campaign.ChargedBudgetMS != charged {
					t.Fatalf("terminal replay replaced evidence/charge: %+v %v", again, err)
				}
				var n int
				if err = d.QueryRow(`SELECT count(*) FROM native_campaign_evidence WHERE task_id=$1`, task.ID).Scan(&n); err != nil || n != 1 {
					t.Fatalf("replay rows %d %v", n, err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid/failed finalization accepted")
			}
			if (mode == "current_mismatch" || mode == "expired") && NativeCampaignErrorCode(err) != "lease_lost" {
				t.Fatalf("ownership/lease gate returned wrong error: %v", err)
			}
			if strings.HasSuffix(mode, "failure") && !strings.Contains(err.Error(), "injected atomic evidence failure") {
				t.Fatalf("wrong failure stage: %v", err)
			}
			afterC, _ := json.Marshal(t3ReloadCampaign(t, d, c))
			afterA, _ := json.Marshal(t3ReloadAttempt(t, d, a))
			if string(afterC) != string(beforeCampaign) || string(afterA) != string(beforeAttempt) {
				t.Fatal("failed finalization changed campaign/attempt/charge")
			}
			var n, events int
			if err = d.QueryRow(`SELECT count(*) FROM native_campaign_evidence WHERE task_id=$1`, task.ID).Scan(&n); err != nil || n != 0 {
				t.Fatalf("orphan metadata committed %d %v", n, err)
			}
			if err = d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE task_id=$1`, task.ID).Scan(&events); err != nil || events != eventsBefore {
				t.Fatal("failed finalization appended events")
			}
		})
	}
}

func TestNativeCampaignAtomicEvidenceConcurrentFinalize(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "atomic-concurrent")
	c := t3CreateDraft(t, d, task, artifact, "atomic-concurrent")
	c = t3Start(t, d, c, c.StateVersion, t3ReqID("atomic-concurrent"), nil)
	a := t3MustClaim(t, d, task, c, "atomic-concurrent").Attempt
	// Active/no-hold cannot be manufactured through a valid database update.
	if _, err = d.Exec(`UPDATE native_campaign_attempts SET resource_hold=false,hold_reason=NULL,cleanup_status='verified' WHERE id=$1`, a.ID); err == nil {
		t.Fatal("active hold invariant was weakened")
	}
	input := &NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/concurrent.json", task.ID, c.ID), SHA256: nativeCampaignHash("concurrent"), Observation: json.RawMessage(`{}`)}
	cmd := NativeCampaignFinalizeCommand{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, FencingToken: a.FencingToken, LeaseOwner: a.LeaseOwner, LeaseInstance: a.LeaseInstance, TargetState: "completed", CleanupStatus: "verified", EvidenceInput: input, ActorKind: "admin", ActualElapsedMS: 1000, CleanupReserveMS: 1000}
	type outcome struct {
		result *NativeCampaignFinalizeResult
		err    error
	}
	done := make(chan outcome, 2)
	start := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			r, e := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, cmd)
			done <- outcome{r, e}
		}()
	}
	close(start)
	first, second := <-done, <-done
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent finalize errors: %v %v", first.err, second.err)
	}
	if first.result.AlreadyFinalized == second.result.AlreadyFinalized || first.result.Attempt.EvidenceManifestID == nil || second.result.Attempt.EvidenceManifestID == nil || *first.result.Attempt.EvidenceManifestID != *second.result.Attempt.EvidenceManifestID || first.result.Campaign.ChargedBudgetMS != second.result.Campaign.ChargedBudgetMS {
		t.Fatal("concurrent finalization did not converge")
	}
	var count, charges int
	if err = d.QueryRow(`SELECT count(*) FROM native_campaign_evidence WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("evidence count %d %v", count, err)
	}
	if err = d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE task_id=$1 AND kind='budget.charged'`, task.ID).Scan(&charges); err != nil || charges != 1 {
		t.Fatalf("charge count %d %v", charges, err)
	}
}

// Block the checkpoint SELECT after the old application-clock gate. Natural DB
// expiry during that wait must be rejected by the new pre-INSERT DB-clock gate.
func TestNativeCampaignAtomicEvidenceDBClockAfterWait(t *testing.T){
 d,err:=Open(fuzzTestDSN(t));if err!=nil{t.Fatal(err)};t.Cleanup(func(){_ = d.Close()})
 task,artifact:=newNativeCampaignTask(t,d,"atomic-db-clock")
 c:=t3CreateDraft(t,d,task,artifact,"atomic-db-clock");c=t3Start(t,d,c,c.StateVersion,t3ReqID("atomic-clock"),nil)
 a:=t3MustClaim(t,d,task,c,"atomic-clock").Attempt
 cp:=t3Checkpoint(t,d,task,c,a,"atomic-clock")
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 blocker,err:=d.BeginTx(ctx,nil);if err!=nil{cancel();t.Fatal(err)}
 var blockerPID int
 if err=blocker.QueryRowContext(ctx,`SELECT pg_backend_pid()`).Scan(&blockerPID);err!=nil{blocker.Rollback();cancel();t.Fatal(err)}
 // Configure the synthetic lease before locking the referenced table: the
 // attempt UPDATE's immediate pointer constraint also accesses checkpoints.
 if _,err=d.ExecContext(ctx,`UPDATE native_campaign_attempts SET lease_expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1`,a.ID);err!=nil{blocker.Rollback();cancel();t.Fatal(err)}
 if _,err=blocker.ExecContext(ctx,`LOCK TABLE native_campaign_checkpoints IN ACCESS EXCLUSIVE MODE`);err!=nil{blocker.Rollback();cancel();t.Fatal(err)}
 input:=&NativeCampaignEvidenceInput{TaskID:task.ID,CampaignID:c.ID,AttemptID:a.ID,Kind:"attempt_final",ResultPath:fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/clock.json",task.ID,c.ID),SHA256:nativeCampaignHash("clock"),Observation:json.RawMessage(`{}`)}
 cmd:=NativeCampaignFinalizeCommand{TaskID:task.ID,CampaignID:c.ID,AttemptID:a.ID,FencingToken:a.FencingToken,LeaseOwner:a.LeaseOwner,LeaseInstance:a.LeaseInstance,TargetState:"failed",CleanupStatus:"unknown",CheckpointID:&cp.ID,EvidenceInput:input,ActorKind:"admin",ActualElapsedMS:1000,CleanupReserveMS:1000}
 done:=make(chan error,1);exited:=make(chan struct{})
 go func(){defer close(exited);_,e:=d.FinalizeNativeCampaignAttempt(ctx,t3AllowAuth,cmd);done<-e}()
 defer func(){cancel();_ = blocker.Rollback();select{case <-exited:case <-time.After(3*time.Second):t.Error("finalizer did not exit after cancellation/unlock")}}()
 for {
  var waiting bool
  if err=d.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%SELECT state FROM native_campaign_checkpoints%')`,blockerPID).Scan(&waiting);err!=nil{t.Fatal(err)}
  if waiting{break}
  select{case e:=<-done:t.Fatalf("did not reach post-app-clock checkpoint lock: %v",e);case <-ctx.Done():t.Fatal(ctx.Err());case <-time.After(10*time.Millisecond):}
 }
 for {
  var expired bool
  if err=d.QueryRowContext(ctx,`SELECT clock_timestamp()>=lease_expires_at FROM native_campaign_attempts WHERE id=$1`,a.ID).Scan(&expired);err!=nil{t.Fatal(err)}
  if expired{break}
  select{case <-ctx.Done():t.Fatal(ctx.Err());case <-time.After(10*time.Millisecond):}
 }
 if err=blocker.Commit();err!=nil{t.Fatal(err)}
 select{case err=<-done:case <-ctx.Done():t.Fatal(ctx.Err())}
 var domain *NativeCampaignError
 if !errors.As(err,&domain)||domain.Code!="lease_lost"||domain.Message!="final evidence lease expired"{t.Fatalf("did not hit post-wait DB-clock evidence gate: %v",err)}
 var rows int;if err=d.QueryRow(`SELECT count(*) FROM native_campaign_evidence WHERE task_id=$1`,task.ID).Scan(&rows);err!=nil||rows!=0{t.Fatal("expired wait published metadata")}
 after:=t3ReloadAttempt(t,d,a)
 if !after.ResourceHold||after.EvidenceManifestID!=nil||after.State!=a.State{t.Fatal("expired wait changed attempt")}
}
