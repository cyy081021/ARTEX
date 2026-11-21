package db

import (
	"context"
	"testing"
	"time"
)

// T4a lease CAS tests use the real isolated PostgreSQL schema and the T3 claim
// path. They never start a runner, Docker, AFL or an external target.

func nativeCampaignLeaseIdentityOf(attempt *NativeCampaignAttempt) NativeCampaignLeaseIdentity {
	return NativeCampaignLeaseIdentity{
		TaskID: attempt.TaskID, CampaignID: attempt.CampaignID, AttemptID: attempt.ID,
		FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner,
		LeaseInstance: attempt.LeaseInstance,
	}
}

func TestNativeCampaignLeaseRenewAndExpiry(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-renew")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-renew")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-renew-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-renew-1")
	attempt := claim.Attempt
	identity := nativeCampaignLeaseIdentityOf(attempt)

	before := attempt.LeaseExpiresAt
	renewed, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	})
	if err != nil {
		t.Fatalf("renew live lease: %v", err)
	}
	if !renewed.Attempt.LeaseExpiresAt.After(before) {
		t.Fatalf("lease not extended: before=%s after=%s", before, renewed.Attempt.LeaseExpiresAt)
	}

	wrong := identity
	wrong.FencingToken++
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: wrong, LeaseMS: 30000,
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("wrong fence renew err=%v code=%q", err, NativeCampaignErrorCode(err))
	}
	wrong = identity
	wrong.LeaseInstance = "foreign-instance"
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: wrong, LeaseMS: 30000,
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("wrong instance renew err=%v", err)
	}

	// Expire the durable lease with the database clock. A late heartbeat must
	// not revive it.
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND id=$2`, task.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("expired lease renewal err=%v code=%q", err, NativeCampaignErrorCode(err))
	}
}

func TestNativeCampaignLeaseMarkStartedCAS(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-start")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-start")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-start-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-start-1")
	attempt := claim.Attempt
	identity := nativeCampaignLeaseIdentityOf(attempt)

	started, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "startup",
		OwnedResources: []byte(`{"container_name":"artex-campaign-owned"}`),
	})
	if err != nil {
		t.Fatalf("mark started: %v", err)
	}
	if started.Attempt.State != "launching" || started.Attempt.StartedAt == nil {
		t.Fatalf("started attempt=%+v", started.Attempt)
	}
	if string(started.Attempt.OwnedResources) == "" || string(started.Attempt.OwnedResources) == "{}" {
		t.Fatalf("owned_resources not persisted: %s", started.Attempt.OwnedResources)
	}
	// started_at is established exactly once.
	if _, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "startup",
		OwnedResources: []byte(`{"container_name":"second"}`),
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("second mark started err=%v code=%q", err, NativeCampaignErrorCode(err))
	}

	// A live lease can be renewed while launching but an expired one cannot and
	// must prevent the start CAS from succeeding.
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND id=$2`, task.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("expired renew err=%v", err)
	}
}

func TestNativeCampaignLeaseHaltKeepsHoldAndRejectsLateWrites(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-halt")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-halt")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-halt-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-halt-1")
	attempt := claim.Attempt
	identity := nativeCampaignLeaseIdentityOf(attempt)
	if _, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "startup", OwnedResources: []byte(`{"container_name":"owned"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND id=$2`, task.ID, attempt.ID); err != nil {
		t.Fatal(err)
	}
	halted, err := d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: identity, Reason: "lease_expired", ActualElapsedMS: 2500,
	})
	if err != nil {
		t.Fatalf("halt lost lease: %v", err)
	}
	if halted.Attempt.State != "interrupted" || halted.Attempt.CleanupStatus != "unknown" || !halted.Attempt.ResourceHold {
		t.Fatalf("halted attempt=%+v", halted.Attempt)
	}
	if halted.Campaign.State != "interrupted" || halted.Campaign.CleanupStatus != "unknown" {
		t.Fatalf("halted campaign=%+v", halted.Campaign)
	}
	if halted.Attempt.ChargedBudgetMS != halted.Attempt.ReservedBudgetMS ||
		halted.Campaign.ChargedBudgetMS != halted.Attempt.ReservedBudgetMS {
		t.Fatalf("lost lease was not conservatively charged: attempt=%+v campaign=%+v",
			halted.Attempt, halted.Campaign)
	}
	// Idempotent same-token halt is safe; a late renewal and a late finalize are not.
	if _, err := d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: identity, Reason: "lease_expired", ActualElapsedMS: 2500,
	}); err != nil {
		t.Fatalf("idempotent halt: %v", err)
	}
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	}); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("terminal renew err=%v", err)
	}
	evidence := t3Evidence(t, d, task, halted.Campaign, halted.Attempt)
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		FencingToken: attempt.FencingToken, LeaseOwner: attempt.LeaseOwner,
		LeaseInstance: attempt.LeaseInstance, TargetState: "failed",
		CleanupStatus: "unknown", EvidenceID: evidence.ID, ActualElapsedMS: 2500,
	}))
	if err == nil {
		t.Fatal("late finalize after lease halt was accepted")
	}

	// Only a verified cleanup retry releases the hold; no target is executed.
	retried, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		CleanupVerified: true, CleanupElapsedMS: 1000,
	})
	if err != nil {
		t.Fatalf("cleanup retry: %v", err)
	}
	if retried.Attempt.ResourceHold || retried.Attempt.CleanupStatus != "verified" {
		t.Fatalf("cleanup retry attempt=%+v", retried.Attempt)
	}
	if retried.Campaign.State != "cancelled" {
		t.Fatalf("cleanup retry campaign=%+v", retried.Campaign)
	}

	// Halt with a stale token cannot mutate a different/terminal attempt.
	foreign := identity
	foreign.FencingToken++
	if _, err := d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: foreign, Reason: "stale",
	}); err == nil {
		t.Fatal("foreign-token halt was accepted")
	}
}

func TestNativeCampaignLeaseHaltDoesNotClaimCleanupVerified(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-unknown")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-unknown")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-unknown-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-unknown-1")
	identity := nativeCampaignLeaseIdentityOf(claim.Attempt)
	if _, err := d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: identity, Reason: "lease_renew_failed", ActualElapsedMS: 9000,
	}); err != nil {
		t.Fatal(err)
	}
	attempt := t3ReloadAttempt(t, d, claim.Attempt)
	if attempt.CleanupStatus == "verified" || !attempt.ResourceHold {
		t.Fatalf("halt falsely released/verified cleanup: %+v", attempt)
	}
	if attempt.StartedAt == nil && (attempt.ChargedBudgetMS != 0 || attempt.ActualElapsedMS != 9000) {
		t.Fatalf("pre-start revocation charged budget: %+v", attempt)
	}
	// A second campaign on the same worker slot must be refused by the global hold.
	otherTask, otherArtifact := newNativeCampaignTask(t, d, "lease-unknown-other")
	other := t3CreateDraft(t, d, otherTask, otherArtifact, "lease-unknown-other")
	other = t3Start(t, d, other, other.StateVersion, t3ReqID("lease-unknown-other-start"), nil)
	_, err = t3Claim(t, d, otherTask, other, "lease-unknown-other-1", nil)
	if err == nil || NativeCampaignErrorCode(err) != "resource_held" {
		t.Fatalf("claim while hold active err=%v code=%q", err, NativeCampaignErrorCode(err))
	}
}

func TestNativeCampaignLeaseValidationAndDBClock(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-validation")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-validation")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-validation-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-validation-1")
	identity := nativeCampaignLeaseIdentityOf(claim.Attempt)

	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 999,
	}); err == nil {
		t.Fatal("sub-1s lease accepted")
	}
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: NativeCampaignLeaseIdentity{},
		LeaseMS:                     30000,
	}); err == nil {
		t.Fatal("empty identity accepted")
	}
	if _, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "not_a_phase",
		OwnedResources: []byte(`{}`),
	}); err == nil {
		t.Fatal("invalid phase accepted")
	}
	// owned_resources must be a bounded JSON object, not an arbitrary blob.
	if _, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "startup",
		OwnedResources: []byte(`[]`),
	}); err == nil {
		t.Fatal("array owned_resources accepted")
	}
	// The DB now() check is authoritative even if this process clock is skewed.
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()+interval '30 seconds'
		WHERE task_id=$1 AND id=$2`, task.ID, claim.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	renewed, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	})
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(renewed.Attempt.LeaseExpiresAt) < 20*time.Second {
		t.Fatalf("DB-clock renewal did not extend lease: %s", renewed.Attempt.LeaseExpiresAt)
	}
}

func TestNativeCampaignLeaseStartPermissionSeparateFromRenew(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "lease-start-gate")
	campaign := t3CreateDraft(t, d, task, artifact, "lease-start-gate")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("lease-start-gate-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "lease-start-gate-1")
	identity := nativeCampaignLeaseIdentityOf(claim.Attempt)
	started, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity, Phase: "startup",
		OwnedResources: []byte(`{"container_name":"start-gate"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	identity = nativeCampaignLeaseIdentityOf(started.Attempt)
	if _, err := d.CheckNativeCampaignAttemptStart(context.Background(), identity); err != nil {
		t.Fatalf("running attempt failed start permission: %v", err)
	}

	// Renew legally continues while stopping, but Start must be rejected.
	if _, err := d.Exec(`UPDATE native_campaigns SET state='stopping', desired_state='paused'
		WHERE task_id=$1 AND id=$2`, task.ID, campaign.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RenewNativeCampaignAttemptLease(context.Background(), NativeCampaignLeaseCommand{
		NativeCampaignLeaseIdentity: identity, LeaseMS: 30000,
	}); err != nil {
		t.Fatalf("renew should remain legal while stopping: %v", err)
	}
	if _, err := d.CheckNativeCampaignAttemptStart(context.Background(), identity); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("stopping campaign passed start permission: err=%v code=%q", err, NativeCampaignErrorCode(err))
	}

	if _, err := d.Exec(`UPDATE native_campaigns SET state='running', desired_state='running'
		WHERE task_id=$1 AND id=$2`, task.ID, campaign.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CheckNativeCampaignAttemptStart(context.Background(), identity); err != nil {
		t.Fatalf("restored running campaign failed start permission: %v", err)
	}
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND id=$2`, task.ID, started.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CheckNativeCampaignAttemptStart(context.Background(), identity); NativeCampaignErrorCode(err) != "lease_lost" {
		t.Fatalf("expired lease passed start permission: err=%v code=%q", err, NativeCampaignErrorCode(err))
	}
}
