package db

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// A lost final frame leaves a started attempt with a resource plan but no creation
// seal, which the sealed retry can never settle. The operator path must release exactly
// that hold, and only when the caller has verified the planned resources are gone.
func TestSettleUnsealedNativeCampaignCleanup(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	task, artifact := newNativeCampaignTask(t, d, "unsealed-settle")
	campaign := t3CreateDraft(t, d, task, artifact, "unsealed-settle")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("unsealed-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "unsealed-instance")
	attempt := claim.Attempt
	identity := nativeCampaignLeaseIdentityOf(attempt)

	// The runner acknowledges start with the resource plan and only later (at finalize)
	// provides the creation seal. Losing the final frame in between is the production
	// case that used to hold the single worker slot forever.
	names := unsealedPlanNames(campaign.ID, attempt.ID, attempt.FencingToken)
	plan := map[string]any{"resource_plan": map[string]any{
		"version": 1, "task_id": task.ID, "campaign_id": campaign.ID,
		"attempt_id": attempt.ID, "fencing_token": attempt.FencingToken,
		"staging_root": "/tmp/artex-campaign-fixture", "staging_basename": names[0] + "-stage",
		"container_names": names,
	}}
	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{
		NativeCampaignLeaseIdentity: identity,
		Phase:                       "startup",
		OwnedResources:              rawPlan,
	}); err != nil {
		t.Fatalf("mark started: %v", err)
	}
	if _, err = d.HaltNativeCampaignAttemptForLeaseLoss(context.Background(), NativeCampaignLeaseHaltCommand{
		NativeCampaignLeaseIdentity: identity,
		Reason:                      "runner_lost",
	}); err != nil {
		t.Fatalf("halt: %v", err)
	}
	held, err := d.NativeCampaignAttempt(context.Background(), task.ID, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !held.ResourceHold || held.CleanupStatus != "unknown" {
		t.Fatalf("expected a held unknown attempt, got hold=%v cleanup=%s", held.ResourceHold, held.CleanupStatus)
	}

	cmd := NativeCampaignCleanupCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		CleanupVerified: true, CleanupElapsedMS: 12, ActorKind: "admin",
	}
	// Without the explicit operator wrapper the plan path stays sealed-only.
	if _, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, cmd); err == nil {
		t.Fatal("legacy cleanup retry must not settle an unsealed plan")
	}
	result, err := d.SettleUnsealedNativeCampaignCleanup(context.Background(), t3AllowAuth, cmd)
	if err != nil {
		t.Fatalf("settle: %v", err)
	}
	if result.Attempt.ResourceHold || result.Attempt.CleanupStatus != "verified" {
		t.Fatalf("attempt not settled: hold=%v cleanup=%s", result.Attempt.ResourceHold, result.Attempt.CleanupStatus)
	}
	if result.Campaign.CleanupStatus != "verified" {
		t.Fatalf("campaign not settled: %s", result.Campaign.CleanupStatus)
	}
	var holdCount int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1 AND resource_hold`, task.ID).Scan(&holdCount); err != nil {
		t.Fatal(err)
	}
	if holdCount != 0 {
		t.Fatalf("slot still held: %d", holdCount)
	}
	var events int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE campaign_id=$1 AND kind='cleanup.verified'`, campaign.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("expected one cleanup.verified event, got %d", events)
	}
	// Idempotence: the second call must be a clean conflict, never a second release.
	if _, err := d.SettleUnsealedNativeCampaignCleanup(context.Background(), t3AllowAuth, cmd); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("second settle = %v, want state_conflict", err)
	}
}

// unsealedPlanNames mirrors the resource-plan naming rule used by the runner and the
// manager (artex-campaign-<campaign>-<attempt>-<attempt>-<fence> plus probe suffixes).
func unsealedPlanNames(campaignID, attemptID, fence int64) []string {
	base := fmt.Sprintf("artex-campaign-%d-%d-%d-%d", campaignID, attemptID, attemptID, fence)
	return []string{base, base + "-help-afl-fuzz", base + "-help-afl-showmap", base + "-probe"}
}
