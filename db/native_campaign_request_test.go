package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestNativeCampaignClaim(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("explicit_authorization_required", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "claim-auth")
		campaign := t3CreateDraft(t, d, task, artifact, "claim-auth")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("claim-auth-start"), nil)
		if _, err := d.ClaimNativeCampaignAttempt(context.Background(), nil, NativeCampaignClaimCommand{
			TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: "nil-auth",
			ProfileMaxDurationMS: 600000, PolicyMaxDurationMS: 600000,
		}); NativeCampaignErrorCode(err) != "authorization_revoked" {
			t.Fatalf("nil authorizer code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if _, err := d.ClaimNativeCampaignAttempt(context.Background(), t3DenyAuth, NativeCampaignClaimCommand{
			TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: "denied-auth",
			ProfileMaxDurationMS: 600000, PolicyMaxDurationMS: 600000,
		}); NativeCampaignErrorCode(err) != "authorization_revoked" {
			t.Fatalf("denied authorizer code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 0 {
			t.Fatalf("denied claim created attempts: %d", got)
		}
		if got := t3ReloadCampaign(t, d, campaign); got.State != "queued" || got.StateVersion != 2 {
			t.Fatalf("denied claim changed campaign: %+v", got)
		}
	})

	t.Run("claim_reserves_and_inserts_runs_and_event", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "claim-success")
		campaign := t3CreateDraft(t, d, task, artifact, "claim-success")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("claim-success-start"), nil)
		claim := t3MustClaim(t, d, task, campaign, "success-instance")
		if claim.Attempt.AttemptNo != 1 || !claim.Attempt.ResourceHold ||
			claim.Attempt.State != "claimed" || claim.Attempt.LeaseOwner != NativeCampaignWorkerSlot ||
			claim.Plan.ExecutionWindowMS != 55000 {
			t.Fatalf("claim=%+v plan=%+v", claim.Attempt, claim.Plan)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		if campaign.State != "running" || campaign.CurrentAttemptID == nil ||
			*campaign.CurrentAttemptID != claim.Attempt.ID || campaign.StateVersion != 3 {
			t.Fatalf("campaign after claim=%+v", campaign)
		}
		var runtimeStatus, profile, mode, target string
		if err := d.QueryRow(`SELECT r.status, r.profile_id, n.mode, n.target_state
			FROM reverse_runtime_runs r JOIN reverse_native_runs n ON n.run_id=r.id
			WHERE r.id=$1 AND r.task_id=$2`, claim.Attempt.RuntimeRunID, task.ID).
			Scan(&runtimeStatus, &profile, &mode, &target); err != nil {
			t.Fatal(err)
		}
		if runtimeStatus != "running" || profile != "lab-linux" || mode != "campaign" || target != "running" {
			t.Fatalf("claim run rows status=%s profile=%s mode=%s target=%s", runtimeStatus, profile, mode, target)
		}
		if got := t3EventKindCount(t, d, task.ID, campaign.ID, "attempt.claimed"); got != 1 {
			t.Fatalf("attempt.claimed events=%d", got)
		}
		if _, err := t3Claim(t, d, task, campaign, "success-instance-2", nil); NativeCampaignErrorCode(err) != "state_conflict" {
			t.Fatalf("second claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 1 {
			t.Fatalf("second claim created attempts: %d", got)
		}
	})

	t.Run("claim_rollback_leaves_no_attempt_or_run", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "claim-rollback")
		campaign := t3CreateDraft(t, d, task, artifact, "claim-rollback")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("claim-rollback-start"), nil)
		ctx := withNativeCampaignFault(context.Background(), func(action string) error {
			if action == "claim" {
				return errors.New("synthetic claim failure")
			}
			return nil
		})
		if _, err := d.ClaimNativeCampaignAttempt(ctx, t3AllowAuth, NativeCampaignClaimCommand{
			TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: "rollback-instance",
			ProfileMaxDurationMS: 600000, PolicyMaxDurationMS: 600000,
		}); NativeCampaignErrorCode(err) != "internal" {
			t.Fatalf("injected claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		for name, table := range map[string]string{"attempts": "attempts", "runs": "runs", "runtime": "runtime"} {
			if got := t3Count(t, d, table, task.ID); got != 0 {
				t.Fatalf("rolled-back claim left %s rows: %d", name, got)
			}
		}
		if got := t3ReloadCampaign(t, d, campaign); got.State != "queued" || got.StateVersion != 2 {
			t.Fatalf("rolled-back claim changed campaign: %+v", got)
		}
		claim := t3MustClaim(t, d, task, campaign, "rollback-instance-retry")
		if claim.Attempt.AttemptNo != 1 {
			t.Fatalf("retry attempt_no=%d", claim.Attempt.AttemptNo)
		}
	})

	t.Run("budget_boundaries_reject_without_attempt", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "claim-budget")
		campaign := t3CreateDraft(t, d, task, artifact, "claim-budget")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("claim-budget-start"), nil)
		below := int64(5999)
		if _, err := t3Claim(t, d, task, campaign, "below-min", &below); NativeCampaignErrorCode(err) != "invalid_request" {
			t.Fatalf("below-min claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		tooMuch := int64(600001)
		if _, err := t3Claim(t, d, task, campaign, "above-remaining", &tooMuch); NativeCampaignErrorCode(err) != "budget_exhausted" {
			t.Fatalf("above-remaining claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 0 {
			t.Fatalf("rejected claims created attempts: %d", got)
		}

		exhausted := t3CreateDraftWithBudget(t, d, task, artifact, "claim-budget-exhausted", 6000)
		exhausted = t3Start(t, d, exhausted, exhausted.StateVersion, t3ReqID("claim-exhausted-start"), nil)
		// Make remaining 5999 (< 6000) without changing the immutable total.
		if _, err := d.Exec(`UPDATE native_campaigns SET charged_budget_ms=1
			WHERE task_id=$1 AND id=$2`, task.ID, exhausted.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := t3Claim(t, d, task, exhausted, "exhausted-instance", nil); NativeCampaignErrorCode(err) != "budget_exhausted" {
			t.Fatalf("exhausted claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
	})
}

func TestNativeCampaignClaimGlobalResourceHold(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "hold")
	a := t3CreateDraft(t, d, task, artifact, "hold-a")
	b := t3CreateDraft(t, d, task, artifact, "hold-b")
	a = t3Start(t, d, a, a.StateVersion, t3ReqID("hold-a-start"), nil)
	b = t3Start(t, d, b, b.StateVersion, t3ReqID("hold-b-start"), nil)
	claimA := t3MustClaim(t, d, task, a, "hold-a-instance")
	if _, err := t3Claim(t, d, task, b, "hold-b-instance", nil); NativeCampaignErrorCode(err) != "resource_held" {
		t.Fatalf("B claim while A holds code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	a = t3ReloadCampaign(t, d, a)
	evidence := t3Evidence(t, d, task, a, claimA.Attempt)
	failed := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: a.ID, AttemptID: claimA.Attempt.ID,
		FencingToken: claimA.Attempt.FencingToken, LeaseOwner: claimA.Attempt.LeaseOwner,
		LeaseInstance: claimA.Attempt.LeaseInstance, TargetState: "failed",
		CleanupStatus: "unknown", EvidenceID: evidence.ID,
		ActualElapsedMS: 4000, CleanupElapsedMS: 61000,
	})
	if failed.Campaign.State != "failed" || failed.Campaign.CleanupStatus != "unknown" {
		t.Fatalf("A failed/unknown=%+v", failed.Campaign)
	}
	if !failed.Attempt.ResourceHold || failed.Attempt.HoldReason == nil || *failed.Attempt.HoldReason != "cleanup_unknown" {
		t.Fatalf("A attempt hold=%+v", failed.Attempt)
	}
	if _, err := t3Claim(t, d, task, b, "hold-b-instance-2", nil); NativeCampaignErrorCode(err) != "resource_held" {
		t.Fatalf("B claim with A cleanup unknown code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	cleanup, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
		TaskID: task.ID, CampaignID: a.ID, AttemptID: claimA.Attempt.ID,
		CleanupVerified: true, CleanupElapsedMS: 1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup.Campaign.State != "failed" || cleanup.Campaign.CleanupStatus != "verified" {
		t.Fatalf("cleanup retry changed failed state: %+v", cleanup.Campaign)
	}
	if cleanup.Attempt.ResourceHold || cleanup.Attempt.CleanupStatus != "verified" {
		t.Fatalf("cleanup retry attempt=%+v", cleanup.Attempt)
	}
	if _, err := t3Claim(t, d, task, b, "hold-b-instance-3", nil); err != nil {
		t.Fatalf("B claim after A cleanup verified: %v", err)
	}
}

func TestNativeCampaignFence(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "fence")
	campaign := t3CreateDraft(t, d, task, artifact, "fence")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("fence-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "fence-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	beforeEvents := t3Count(t, d, "events", task.ID)
	beforeCharged := campaign.ChargedBudgetMS
	beforeVersion := campaign.StateVersion

	assertNoFenceSideEffects := func(label string, err error) {
		t.Helper()
		if NativeCampaignErrorCode(err) != "lease_lost" {
			t.Fatalf("%s code=%q err=%v", label, NativeCampaignErrorCode(err), err)
		}
		gotCampaign := t3ReloadCampaign(t, d, campaign)
		gotAttempt := t3ReloadAttempt(t, d, claim.Attempt)
		if gotCampaign.State != "running" || gotCampaign.StateVersion != beforeVersion ||
			gotCampaign.ChargedBudgetMS != beforeCharged {
			t.Fatalf("%s campaign side effect: %+v", label, gotCampaign)
		}
		if gotAttempt.State != "claimed" || gotAttempt.ChargedBudgetMS != 0 ||
			gotAttempt.ActualElapsedMS != 0 || gotAttempt.CleanupStatus != "pending" {
			t.Fatalf("%s attempt side effect: %+v", label, gotAttempt)
		}
		if got := t3Count(t, d, "events", task.ID); got != beforeEvents {
			t.Fatalf("%s appended events: %d -> %d", label, beforeEvents, got)
		}
	}

	base := NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "completed",
		CleanupStatus: "verified", EvidenceID: evidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 500,
	}
	wrongFence := base
	wrongFence.FencingToken++
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(wrongFence))
	assertNoFenceSideEffects("wrong fencing token", err)

	wrongInstance := base
	wrongInstance.LeaseInstance = "other-instance"
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(wrongInstance))
	assertNoFenceSideEffects("wrong lease instance", err)

	if _, err := d.Exec(`UPDATE native_campaign_attempts
		SET lease_expires_at = now() - interval '1 second'
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3`,
		task.ID, campaign.ID, claim.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(base))
	assertNoFenceSideEffects("expired lease", err)

	if _, err := d.Exec(`UPDATE native_campaign_attempts
		SET lease_expires_at = now() + interval '5 minutes'
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3`,
		task.ID, campaign.ID, claim.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	completed := t3MustFinalize(t, d, base)
	if completed.Attempt.State != "completed" || completed.Campaign.State != "completed" {
		t.Fatalf("completed finalize=%+v %+v", completed.Attempt, completed.Campaign)
	}
	charged := completed.Campaign.ChargedBudgetMS
	eventsAfter := t3Count(t, d, "events", task.ID)
	duplicate := t3MustFinalize(t, d, base)
	if !duplicate.AlreadyFinalized {
		t.Fatal("duplicate finalize not idempotent")
	}
	if got := t3ReloadCampaign(t, d, campaign).ChargedBudgetMS; got != charged {
		t.Fatalf("duplicate finalize double-charged: %d -> %d", charged, got)
	}
	if got := t3Count(t, d, "events", task.ID); got != eventsAfter {
		t.Fatalf("duplicate finalize appended events: %d -> %d", eventsAfter, got)
	}
	otherTarget := base
	otherTarget.TargetState = "paused"
	if _, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(otherTarget)); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("different target code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3ReloadCampaign(t, d, campaign).ChargedBudgetMS; got != charged {
		t.Fatalf("different target changed charge: %d -> %d", charged, got)
	}
}

func TestNativeCampaignStale(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "stale")
	campaign := t3CreateDraft(t, d, task, artifact, "stale")
	beforeRequests := t3Count(t, d, "requests", task.ID)
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("stale-start"),
		ExpectedStateVersion: 99,
	}); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("stale start code=%q err=%v", NativeCampaignErrorCode(err), err)
	} else {
		var campaignErr *NativeCampaignError
		if !errors.As(err, &campaignErr) || campaignErr.StateVersion != 1 || campaignErr.State != "draft" {
			t.Fatalf("stale start details=%+v", campaignErr)
		}
	}
	got := t3ReloadCampaign(t, d, campaign)
	if got.State != "draft" || got.StateVersion != 1 {
		t.Fatalf("stale start changed state: %+v", got)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("deterministic 409 should be recorded once, requests=%d want %d", got, beforeRequests+1)
	}
	var storedStatus int
	if err := d.QueryRow(`SELECT response_status FROM native_campaign_requests
		WHERE task_id=$1 AND request_id LIKE 'stale-start-%' ORDER BY id DESC LIMIT 1`,
		task.ID).Scan(&storedStatus); err != nil || storedStatus != 409 {
		t.Fatalf("stored stale status=%d err=%v", storedStatus, err)
	}
	campaign = t3Start(t, d, campaign, 1, t3ReqID("stale-start-ok"), nil)
	_ = t3MustClaim(t, d, task, campaign, "stale-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	currentVersion := campaign.StateVersion
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("stale-pause"),
		ExpectedStateVersion: currentVersion - 1,
	}); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("stale pause code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	got = t3ReloadCampaign(t, d, campaign)
	if got.State != "running" || got.StateVersion != currentVersion {
		t.Fatalf("stale pause changed campaign: %+v", got)
	}
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("bad-version"),
		ExpectedStateVersion: 0,
	}); NativeCampaignErrorCode(err) != "invalid_request" {
		t.Fatalf("invalid version code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
}

func TestNativeCampaignConcurrentStart(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	runConcurrentStart := func(t *testing.T, task *Task, artifact *ReverseArtifact, sameRequest bool) {
		t.Helper()
		campaign := t3CreateDraft(t, d, task, artifact, fmt.Sprintf("concurrent-start-%v", sameRequest))
		beforeRequests := t3Count(t, d, "requests", task.ID)
		requestIDs := []string{t3ReqID("concurrent-start-a"), t3ReqID("concurrent-start-b")}
		if sameRequest {
			requestIDs[1] = requestIDs[0]
		}
		type result struct {
			resp *NativeCampaignCommandResponse
			err  error
		}
		results := make([]result, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i].resp, results[i].err = d.StartNativeCampaign(context.Background(), t3AllowAuth,
					NativeCampaignStateCommand{
						TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestIDs[i],
						ExpectedStateVersion: 1,
					})
			}(i)
		}
		wg.Wait()
		got := t3ReloadCampaign(t, d, campaign)
		if got.State != "queued" || got.DesiredState != "running" || got.StateVersion != 2 {
			t.Fatalf("concurrent start campaign=%+v", got)
		}
		if got := t3EventKindCount(t, d, task.ID, campaign.ID, "campaign.queued"); got != 1 {
			t.Fatalf("concurrent start queued events=%d", got)
		}
		success := 0
		codes := []string{}
		for _, r := range results {
			if r.err == nil && r.resp != nil && r.resp.Status == 202 {
				success++
			}
			codes = append(codes, NativeCampaignErrorCode(r.err))
			if r.err != nil && NativeCampaignErrorCode(r.err) != "state_conflict" {
				t.Fatalf("unexpected concurrent start error=%v", r.err)
			}
		}
		if sameRequest {
			if success != 2 {
				t.Fatalf("same-request concurrent start success=%d codes=%v", success, codes)
			}
			if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
				t.Fatalf("same-request concurrent start request rows=%d want %d", got, beforeRequests+1)
			}
		} else {
			if success != 1 {
				t.Fatalf("different-request concurrent start success=%d codes=%v", success, codes)
			}
			if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+2 {
				t.Fatalf("different-request concurrent start request rows=%d want %d", got, beforeRequests+2)
			}
		}
	}

	t.Run("same_request_serializes", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "concurrent-start-same")
		runConcurrentStart(t, task, artifact, true)
	})
	t.Run("different_requests_cas_one_winner", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "concurrent-start-diff")
		runConcurrentStart(t, task, artifact, false)
	})
}

func TestNativeCampaignConcurrentResume(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "concurrent-resume")
	campaign, _, _, _ := t3PreparePausedCampaign(t, d, task, artifact, "concurrent-resume")
	expected := campaign.StateVersion
	requestIDs := []string{t3ReqID("concurrent-resume-a"), t3ReqID("concurrent-resume-b")}
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
				TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestIDs[i],
				ExpectedStateVersion: expected,
			})
		}(i)
	}
	wg.Wait()
	success := 0
	for _, err := range results {
		if err == nil {
			success++
		} else if NativeCampaignErrorCode(err) != "state_conflict" {
			t.Fatalf("concurrent resume error=%v", err)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent resume success=%d", success)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if campaign.State != "queued" || campaign.StateVersion != expected+1 {
		t.Fatalf("campaign after concurrent resume=%+v", campaign)
	}

	claimResults := make([]*NativeCampaignClaimResult, 2)
	claimErrors := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			claimResults[i], claimErrors[i] = d.ClaimNativeCampaignAttempt(context.Background(), t3AllowAuth,
				NativeCampaignClaimCommand{
					TaskID: task.ID, CampaignID: campaign.ID,
					LeaseInstance:          fmt.Sprintf("concurrent-resume-instance-%d", i),
					DefaultAttemptBudgetMS: 60000, ProfileMaxDurationMS: 600000,
					PolicyMaxDurationMS: 600000, OperatorKind: "admin",
				})
		}(i)
	}
	wg.Wait()
	claimSuccess := 0
	for _, err := range claimErrors {
		if err == nil {
			claimSuccess++
		} else if code := NativeCampaignErrorCode(err); code != "state_conflict" && code != "resource_held" {
			t.Fatalf("concurrent claim error=%v", err)
		}
	}
	if claimSuccess != 1 {
		t.Fatalf("concurrent claim success=%d", claimSuccess)
	}
	var attempts int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_attempts
		WHERE task_id=$1 AND campaign_id=$2`, task.ID, campaign.ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempt count after resume+claim=%d want 2", attempts)
	}
	var maxNo int
	if err := d.QueryRow(`SELECT max(attempt_no) FROM native_campaign_attempts
		WHERE task_id=$1 AND campaign_id=$2`, task.ID, campaign.ID).Scan(&maxNo); err != nil {
		t.Fatal(err)
	}
	if maxNo != 2 {
		t.Fatalf("attempt_no after resume=%d want 2", maxNo)
	}
}

func TestNativeCampaignTransitionsCleanupRetry(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("failed_stays_failed_and_cannot_rerun", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cleanup-failed")
		campaign := t3CreateDraft(t, d, task, artifact, "cleanup-failed")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("cleanup-failed-start"), nil)
		claim := t3MustClaim(t, d, task, campaign, "cleanup-failed-instance")
		campaign = t3ReloadCampaign(t, d, campaign)
		evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
		res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
			LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "failed",
			CleanupStatus: "unknown", EvidenceID: evidence.ID,
			ActualElapsedMS: 2000, CleanupElapsedMS: 61000,
		})
		charged := res.Campaign.ChargedBudgetMS
		if charged != res.Attempt.ReservedBudgetMS {
			t.Fatalf("failed unknown charged=%d reserved=%d", charged, res.Attempt.ReservedBudgetMS)
		}
		for name, call := range map[string]func() error{
			"start": func() error {
				_, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("failed-start"),
					ExpectedStateVersion: res.Campaign.StateVersion,
				})
				return err
			},
			"resume": func() error {
				_, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("failed-resume"),
					ExpectedStateVersion: res.Campaign.StateVersion,
				})
				return err
			},
			"cancel": func() error {
				_, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("failed-cancel"),
					ExpectedStateVersion: res.Campaign.StateVersion,
				})
				return err
			},
		} {
			if err := call(); NativeCampaignErrorCode(err) != "terminal_campaign" {
				t.Fatalf("failed %s code=%q err=%v", name, NativeCampaignErrorCode(err), err)
			}
		}
		if _, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			CleanupVerified: false, CleanupElapsedMS: 1000,
		}); NativeCampaignErrorCode(err) != "cleanup_unknown" {
			t.Fatalf("unverified cleanup retry code=%q", NativeCampaignErrorCode(err))
		}
		if _, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			CleanupVerified: true, CleanupElapsedMS: 61000,
		}); NativeCampaignErrorCode(err) != "cleanup_unknown" {
			t.Fatalf("hard-timeout cleanup retry code=%q", NativeCampaignErrorCode(err))
		}
		if got := t3ReloadAttempt(t, d, claim.Attempt); !got.ResourceHold || got.CleanupStatus != "unknown" ||
			got.CleanupOverrunMS != 56000 {
			t.Fatalf("failed cleanup timeout released hold or lost overrun: %+v", got)
		}
		retry, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			CleanupVerified: true, CleanupElapsedMS: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if retry.Campaign.State != "failed" || retry.Campaign.CleanupStatus != "verified" {
			t.Fatalf("cleanup retry campaign=%+v", retry.Campaign)
		}
		if retry.Attempt.ResourceHold || retry.Attempt.State != "failed" ||
			retry.Attempt.ChargedBudgetMS != res.Attempt.ChargedBudgetMS {
			t.Fatalf("cleanup retry attempt=%+v", retry.Attempt)
		}
		if got := t3ReloadCampaign(t, d, campaign).ChargedBudgetMS; got != charged {
			t.Fatalf("cleanup retry recharged: %d -> %d", charged, got)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 1 {
			t.Fatalf("cleanup retry created/reran attempts: %d", got)
		}
	})

	t.Run("interrupted_cleanup_retry_cancels_campaign", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cleanup-interrupted")
		campaign := t3CreateDraft(t, d, task, artifact, "cleanup-interrupted")
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("cleanup-interrupted-start"), nil)
		claim := t3MustClaim(t, d, task, campaign, "cleanup-interrupted-instance")
		campaign = t3ReloadCampaign(t, d, campaign)
		evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
		res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
			LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "interrupted",
			CleanupStatus: "unknown", EvidenceID: evidence.ID,
			ActualElapsedMS: 2000, CleanupElapsedMS: 61000,
		})
		if res.Campaign.State != "interrupted" || res.Campaign.CleanupStatus != "unknown" {
			t.Fatalf("interrupted finalize=%+v", res.Campaign)
		}
		if _, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("interrupted-cancel"),
			ExpectedStateVersion: res.Campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "cleanup_unknown" {
			t.Fatalf("interrupted cancel cleanup code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("interrupted-resume"),
			ExpectedStateVersion: res.Campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "cleanup_unknown" {
			t.Fatalf("interrupted resume cleanup code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		retry, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			CleanupVerified: true, CleanupElapsedMS: 1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if retry.Campaign.State != "cancelled" || retry.Campaign.CleanupStatus != "verified" {
			t.Fatalf("interrupted cleanup retry campaign=%+v", retry.Campaign)
		}
		if retry.Attempt.ResourceHold || retry.Attempt.State != "interrupted" {
			t.Fatalf("interrupted cleanup retry attempt=%+v", retry.Attempt)
		}
	})
}

func TestNativeCampaignBudgetInvariantRollsBack(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "budget-invariant")
	campaign := t3CreateDraft(t, d, task, artifact, "budget-invariant")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("budget-invariant-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "budget-invariant-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	// Push charged close to total so charged + ledger > total at finalize. The
	// charge guard permits a monotonic increase; the finalize transaction must
	// fail and roll back rather than clamp.
	if _, err := d.Exec(`UPDATE native_campaigns SET charged_budget_ms=599500
		WHERE task_id=$1 AND id=$2`, task.ID, campaign.ID); err != nil {
		t.Fatal(err)
	}
	beforeEvents := t3Count(t, d, "events", task.ID)
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "completed",
		CleanupStatus: "verified", EvidenceID: evidence.ID,
		ActualElapsedMS: 0, CleanupElapsedMS: 1000,
	}))
	requireNativeCampaignCode(t, err, "budget_invariant")
	if got := t3ReloadCampaign(t, d, campaign); got.ChargedBudgetMS != 599500 ||
		got.State != "running" || got.StateVersion != campaign.StateVersion {
		t.Fatalf("budget invariant rollback campaign=%+v", got)
	}
	if got := t3ReloadAttempt(t, d, claim.Attempt); got.State != "claimed" ||
		got.ChargedBudgetMS != 0 || got.EvidenceManifestID != nil {
		t.Fatalf("budget invariant rollback attempt=%+v", got)
	}
	if got := t3Count(t, d, "events", task.ID); got != beforeEvents {
		t.Fatalf("budget invariant rollback appended events: %d -> %d", beforeEvents, got)
	}
	// Direct proof this is not a clamp: the ledger was never written.
	var charged int64
	if err := d.QueryRow(`SELECT charged_budget_ms FROM native_campaigns
		WHERE task_id=$1 AND id=$2`, task.ID, campaign.ID).Scan(&charged); err != nil {
		t.Fatal(err)
	}
	if charged != 599500 {
		t.Fatalf("charged was clamped to %d", charged)
	}
}

func TestNativeCampaignIdempotentFiveXXNotCached(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-5xx")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-5xx")
	beforeRequests := t3Count(t, d, "requests", task.ID)
	requestID := t3ReqID("idempotent-5xx-start")
	faultCtx := withNativeCampaignFault(context.Background(), func(action string) error {
		if action == "start" {
			return errors.New("synthetic start failure")
		}
		return nil
	})
	if _, err := d.StartNativeCampaign(faultCtx, t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	}); NativeCampaignErrorCode(err) != "internal" {
		t.Fatalf("fault start code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "draft" || got.StateVersion != 1 {
		t.Fatalf("5xx start changed state: %+v", got)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests {
		t.Fatalf("5xx start cached request: %d -> %d", beforeRequests, got)
	}
	resp, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	})
	if err != nil || resp == nil || resp.Replayed {
		t.Fatalf("retry after 5xx resp=%+v err=%v", resp, err)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "queued" || got.StateVersion != 2 {
		t.Fatalf("retry after 5xx state=%+v", got)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("retry after 5xx requests=%d want %d", got, beforeRequests+1)
	}
}

func TestNativeCampaignIdempotentConcurrentSameRequest(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-same")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-same")
	beforeRequests := t3Count(t, d, "requests", task.ID)
	requestID := t3ReqID("same-request")
	type result struct {
		resp *NativeCampaignCommandResponse
		err  error
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i].resp, results[i].err = d.StartNativeCampaign(context.Background(), t3AllowAuth,
				NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
					ExpectedStateVersion: 1,
				})
		}(i)
	}
	wg.Wait()
	replayed := 0
	for _, r := range results {
		if r.err != nil {
			t.Fatalf("same request concurrent error=%v", r.err)
		}
		if r.resp.Replayed {
			replayed++
		}
	}
	if replayed != 1 {
		t.Fatalf("same request replay count=%d want 1", replayed)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.StateVersion != 2 || got.State != "queued" {
		t.Fatalf("same request campaign=%+v", got)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("same request rows=%d want %d", got, beforeRequests+1)
	}
	if got := t3EventKindCount(t, d, task.ID, campaign.ID, "campaign.queued"); got != 1 {
		t.Fatalf("same request queued events=%d", got)
	}
}

func TestNativeCampaignIdempotentConcurrentBound(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-bound")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-bound")
	requestID := t3ReqID("bounded-request")
	tx, err := d.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	key := fmt.Sprintf("%d:%s", task.ID, requestID)
	if _, err := tx.ExecContext(context.Background(),
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))`, key); err != nil {
		t.Fatal(err)
	}
	waitCtx := withNativeCampaignRequestLockWait(context.Background(), 100*time.Millisecond)
	start := time.Now()
	_, err = d.StartNativeCampaign(waitCtx, t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	})
	if NativeCampaignErrorCode(err) != "request_in_progress" {
		t.Fatalf("bounded lock wait code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("request lock wait was not bounded: %v", elapsed)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "draft" || got.StateVersion != 1 {
		t.Fatalf("request_in_progress changed campaign: %+v", got)
	}
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "queued" || got.StateVersion != 2 {
		t.Fatalf("post-lock start campaign=%+v", got)
	}
}

func TestNativeCampaignIdempotentPureReadDoesNotWrite(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-read")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-read")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("idempotent-read-start"), nil)
	beforeRequests := t3Count(t, d, "requests", task.ID)
	beforeEvents := t3Count(t, d, "events", task.ID)
	before := t3ReloadCampaign(t, d, campaign)
	first, err := d.ValidateNativeCampaign(context.Background(), task.ID, campaign.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.ValidateNativeCampaign(context.Background(), task.ID, campaign.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !first.CanStart || !second.CanStart {
		t.Fatalf("queued validate can_start=%v/%v", first.CanStart, second.CanStart)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests {
		t.Fatalf("pure read wrote request rows: %d -> %d", beforeRequests, got)
	}
	if got := t3Count(t, d, "events", task.ID); got != beforeEvents {
		t.Fatalf("pure read wrote events: %d -> %d", beforeEvents, got)
	}
	if after := t3ReloadCampaign(t, d, campaign); after.StateVersion != before.StateVersion ||
		after.State != before.State || after.ChargedBudgetMS != before.ChargedBudgetMS {
		t.Fatalf("pure read changed campaign: %+v -> %+v", before, after)
	}
}

func TestNativeCampaignIdempotentConflictAndReplay(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-conflict")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-conflict")
	beforeRequests := t3Count(t, d, "requests", task.ID)
	requestID := t3ReqID("conflict-start")
	resp, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var firstBody, replayBody map[string]any
	if err := json.Unmarshal(resp.Body, &firstBody); err != nil {
		t.Fatal(err)
	}
	replay, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 1,
	})
	if err != nil || !replay.Replayed {
		t.Fatalf("replay resp=%+v err=%v", replay, err)
	}
	if err := json.Unmarshal(replay.Body, &replayBody); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(firstBody, replayBody) {
		t.Fatalf("replay body changed:\n%v\n%v", firstBody, replayBody)
	}
	if got := t3ReloadCampaign(t, d, campaign).StateVersion; got != 2 {
		t.Fatalf("replay changed version: %d", got)
	}
	// Same request_id, different payload/hash.
	otherBudget := int64(60000)
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 2, AttemptBudgetMS: &otherBudget,
	}); NativeCampaignErrorCode(err) != "idempotency_conflict" {
		t.Fatalf("different hash code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("conflict added request rows: %d -> %d", beforeRequests+1, got)
	}
}

func TestNativeCampaignIdempotentDeterministic4xxCached(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "idempotent-4xx")
	campaign := t3CreateDraft(t, d, task, artifact, "idempotent-4xx")
	beforeRequests := t3Count(t, d, "requests", task.ID)
	requestID := t3ReqID("stale-request")
	cmd := NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: 99,
	}
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, cmd); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("first stale code=%q", NativeCampaignErrorCode(err))
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("deterministic 4xx not stored: %d want %d", got, beforeRequests+1)
	}
	resp, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, cmd)
	if NativeCampaignErrorCode(err) != "state_conflict" || resp == nil || !resp.Replayed || resp.Status != 409 {
		t.Fatalf("4xx replay resp=%+v err=%v", resp, err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeRequests+1 {
		t.Fatalf("4xx replay added rows: %d -> %d", beforeRequests+1, got)
	}
}

func TestNativeCampaignIdempotentCanonicalization(t *testing.T) {
	first, hashFirst, err := CanonicalNativeCampaignRequest("start", map[string]any{
		"campaign_id": int64(7), "expected_state_version": int64(3), "request_id": "a",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, hashSecond, err := CanonicalNativeCampaignRequest("start", map[string]any{
		"expected_state_version": int64(3), "campaign_id": int64(7), "request_id": "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || hashFirst != hashSecond {
		t.Fatalf("canonical order/request_id mismatch:\n%s\n%s", first, second)
	}
	_, otherHash, err := CanonicalNativeCampaignRequest("start", map[string]any{
		"campaign_id": int64(7), "expected_state_version": int64(3), "attempt_budget_ms": int64(6000),
	})
	if err != nil {
		t.Fatal(err)
	}
	if otherHash == hashFirst {
		t.Fatal("different payload produced the same request hash")
	}
	if _, _, err := CanonicalNativeCampaignRequest("start", map[string]any{
		"campaign_id": int64(7), "expected_state_version": float64(3),
	}); NativeCampaignErrorCode(err) != "invalid_request" {
		t.Fatalf("float version code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if _, _, err := CanonicalNativeCampaignRequest("bogus", nil); NativeCampaignErrorCode(err) != "unknown_action" {
		t.Fatalf("unknown action code=%q", NativeCampaignErrorCode(err))
	}
	if err := ValidateNativeCampaignActionFields("start", map[string]any{
		"request_id": "x", "campaign_id": int64(1), "expected_state_version": int64(1), "reason": "x",
	}); NativeCampaignErrorCode(err) != "unknown_field" {
		t.Fatalf("cross-action field code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if err := ValidateNativeCampaignActionFields("create", map[string]any{
		"request_id": "x", "artifact_id": int64(1), "profile_id": "p", "total_budget_ms": int64(6000), "foo": true,
	}); NativeCampaignErrorCode(err) != "unknown_field" {
		t.Fatalf("unknown create field code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if err := ValidateNativeCampaignActionFields("bogus", nil); NativeCampaignErrorCode(err) != "unknown_action" {
		t.Fatalf("unknown action field code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
}

func TestNativeCampaignIdempotent404Associations(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _ := newNativeCampaignTask(t, d, "idempotent-404")
	missingCampaign := int64(999999999)
	requestID := t3ReqID("missing-campaign")
	cmd := NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: missingCampaign, RequestID: requestID,
		ExpectedStateVersion: 1,
	}
	before := t3Count(t, d, "requests", task.ID)
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, cmd); NativeCampaignErrorCode(err) != "not_found" {
		t.Fatalf("missing campaign code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != before+1 {
		t.Fatalf("missing campaign 404 not cached: %d -> %d", before, got)
	}
	var associated *int64
	var status int
	if err := d.QueryRow(`SELECT campaign_id,response_status FROM native_campaign_requests
		WHERE task_id=$1 AND request_id=$2`, task.ID, requestID).Scan(&associated, &status); err != nil {
		t.Fatal(err)
	}
	if associated != nil || status != 404 {
		t.Fatalf("missing campaign 404 association=%v status=%d", associated, status)
	}
	resp, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, cmd)
	if NativeCampaignErrorCode(err) != "not_found" || resp == nil || !resp.Replayed || resp.Status != 404 {
		t.Fatalf("missing campaign replay resp=%+v err=%v", resp, err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != before+1 {
		t.Fatalf("missing campaign replay added rows: %d", got)
	}

	// Cross-task campaign id: task B exists, but campaign belongs to task A.
	otherTask, otherArtifact := newNativeCampaignTask(t, d, "idempotent-404-other")
	crossCampaign := t3CreateDraft(t, d, otherTask, otherArtifact, "idempotent-404-cross")
	crossRequest := t3ReqID("cross-task")
	beforeOther := t3Count(t, d, "requests", task.ID)
	crossCmd := NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: crossCampaign.ID, RequestID: crossRequest,
		ExpectedStateVersion: 1,
	}
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, crossCmd); NativeCampaignErrorCode(err) != "not_found" {
		t.Fatalf("cross-task code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeOther+1 {
		t.Fatalf("cross-task 404 not cached: %d -> %d", beforeOther, got)
	}
	if err := d.QueryRow(`SELECT campaign_id,response_status FROM native_campaign_requests
		WHERE task_id=$1 AND request_id=$2`, task.ID, crossRequest).Scan(&associated, &status); err != nil {
		t.Fatal(err)
	}
	if associated != nil || status != 404 {
		t.Fatalf("cross-task 404 association=%v status=%d", associated, status)
	}
	resp, err = d.StartNativeCampaign(context.Background(), t3AllowAuth, crossCmd)
	if NativeCampaignErrorCode(err) != "not_found" || resp == nil || !resp.Replayed {
		t.Fatalf("cross-task replay resp=%+v err=%v", resp, err)
	}
	if got := t3Count(t, d, "requests", task.ID); got != beforeOther+1 {
		t.Fatalf("cross-task replay added rows: %d", got)
	}

	// A missing task cannot own a request row and must not be cached.
	missingTask := int64(999999998)
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: missingTask, CampaignID: 1, RequestID: t3ReqID("missing-task"),
		ExpectedStateVersion: 1,
	}); NativeCampaignErrorCode(err) != "not_found" {
		t.Fatalf("missing task code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3Count(t, d, "requests", missingTask); got != 0 {
		t.Fatalf("missing task was cached: %d", got)
	}
}

func TestNativeCampaignIdempotentCreateEffectHash(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "create-effect-hash")
	requestID := t3ReqID("create-effect")
	spec := json.RawMessage(`{"engine":"afl++","label":"effect-hash"}`)
	base := NativeCampaignCreateCommand{
		TaskID: task.ID, RequestID: requestID, ArtifactID: artifact.ID,
		ProfileID: "lab-linux", CreatorKind: "admin", CreatorID: 0,
		Spec: spec, ArtifactSHA256: artifact.SHA256,
		ImageDigest:    "sha256:" + nativeCampaignHash("effect-image"),
		ImageID:        "sha256:" + nativeCampaignHash("effect-image-id"),
		PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: 600000,
	}
	resp, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, base)
	if err != nil {
		t.Fatal(err)
	}
	var first struct {
		Campaign NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&first); err != nil {
		t.Fatal(err)
	}
	before := t3Count(t, d, "attempts", task.ID)
	_ = before
	var campaignsBefore int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaigns WHERE task_id=$1`, task.ID).Scan(&campaignsBefore); err != nil {
		t.Fatal(err)
	}

	changedImage := base
	changedImage.ImageID = "sha256:" + nativeCampaignHash("different-image-id")
	if _, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, changedImage); NativeCampaignErrorCode(err) != "idempotency_conflict" {
		t.Fatalf("changed image_id code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	changedCreator := base
	changedCreator.CreatorKind = "intent"
	changedCreator.CreatorID = 7
	if _, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, changedCreator); NativeCampaignErrorCode(err) != "idempotency_conflict" {
		t.Fatalf("changed creator code=%q err=%v", NativeCampaignErrorCode(err), err)
	}

	// Same spec text, different authorized budget gets a different bound hash.
	budget2 := base
	budget2.RequestID = t3ReqID("create-effect-budget")
	budget2.TotalBudgetMS = 700000
	resp2, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, budget2)
	if err != nil {
		t.Fatal(err)
	}
	var second struct {
		Campaign NativeCampaign `json:"campaign"`
	}
	if err := resp2.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if second.Campaign.SpecHash == first.Campaign.SpecHash {
		t.Fatalf("different budget shared spec_hash %s", first.Campaign.SpecHash)
	}

	// A caller-provided spec projection that conflicts with the command is
	// rejected before any campaign is written.
	conflict := base
	conflict.RequestID = t3ReqID("create-effect-conflict")
	conflict.Spec = json.RawMessage(`{"engine":"afl++","total_budget_ms":1}`)
	if _, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, conflict); NativeCampaignErrorCode(err) != "invalid_request" {
		t.Fatalf("projection conflict code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	var campaignsAfter int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaigns WHERE task_id=$1`, task.ID).Scan(&campaignsAfter); err != nil {
		t.Fatal(err)
	}
	if campaignsAfter != campaignsBefore+1 {
		t.Fatalf("projection conflict wrote campaign: %d -> %d", campaignsBefore, campaignsAfter)
	}
}
