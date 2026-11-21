package db

import (
	"context"
	"testing"
	"time"
)

func t5cRecoveryAttempt(t *testing.T, started bool) (*DB, *NativeCampaignAttempt) {
	t.Helper()
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "expired-recovery")
	campaign := t3CreateDraft(t, d, task, artifact, "expired-recovery")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("recovery-start"), nil)
	attempt := t3MustClaim(t, d, task, campaign, t3ReqID("old-owner")).Attempt
	if started {
		result, err := d.MarkNativeCampaignAttemptStarted(context.Background(), NativeCampaignAttemptStartCommand{NativeCampaignLeaseIdentity: nativeCampaignLeaseIdentityOf(attempt), Phase: "startup", OwnedResources: []byte(`{"container_name":"planned-not-proof"}`)})
		if err != nil {
			t.Fatal(err)
		}
		attempt = result.Attempt
	}
	return d, attempt
}
func t5cExpire(t *testing.T, d *DB, a *NativeCampaignAttempt) {
	t.Helper()
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE task_id=$1 AND id=$2`, a.TaskID, a.ID); err != nil {
		t.Fatal(err)
	}
}
func TestNativeCampaignRecoveryExpiredIdentityAndSettlement(t *testing.T) {
	for _, mode := range []string{"live", "started", "claimed", "wrong_fence", "wrong_instance"} {
		t.Run(mode, func(t *testing.T) {
			d, a := t5cRecoveryAttempt(t, mode != "claimed")
			identity := nativeCampaignLeaseIdentityOf(a)
			if mode != "live" {
				t5cExpire(t, d, a)
			}
			if mode == "wrong_fence" {
				identity.FencingToken++
			}
			if mode == "wrong_instance" {
				identity.LeaseInstance = "foreign-instance"
			}
			result, err := d.ReconcileExpiredNativeCampaignAttempt(context.Background(), identity)
			if mode == "live" || mode == "wrong_fence" || mode == "wrong_instance" {
				want := "lease_lost"
				if mode == "live" {
					want = "lease_active"
				}
				if NativeCampaignErrorCode(err) != want {
					t.Fatalf("unexpected rejection: %v", err)
				}
				unchanged, e := d.NativeCampaignAttempt(context.Background(), a.TaskID, a.ID)
				if e != nil {
					t.Fatal(e)
				}
				if unchanged.State != a.State || unchanged.ChargedBudgetMS != a.ChargedBudgetMS || !unchanged.ResourceHold {
					t.Fatal("rejected recovery changed owner state")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Attempt.State != "interrupted" || result.Attempt.CleanupStatus != "unknown" || !result.Attempt.ResourceHold || result.Campaign.DesiredState != "none" || result.Attempt.FencingToken != a.FencingToken {
				t.Fatalf("unsafe recovery: %+v", result)
			}
			expected := a.ReservedBudgetMS
			if mode == "claimed" {
				expected = 0
			}
			if result.Attempt.ChargedBudgetMS != expected {
				t.Fatalf("charged %d want %d", result.Attempt.ChargedBudgetMS, expected)
			}
			again, e := d.ReconcileExpiredNativeCampaignAttempt(context.Background(), identity)
			if e != nil {
				t.Fatal(e)
			}
			if again.Campaign.ChargedBudgetMS != result.Campaign.ChargedBudgetMS {
				t.Fatal("idempotent recovery charged twice")
			}
			var count int
			if err := d.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1 AND campaign_id=$2`, a.TaskID, a.CampaignID).Scan(&count); err != nil || count != 1 {
				t.Fatalf("recovery created attempt: %d %v", count, err)
			}
		})
	}
}
func TestNativeCampaignRecoveryConcurrentIdempotent(t *testing.T) {
	d, a := t5cRecoveryAttempt(t, true)
	t5cExpire(t, d, a)
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := d.ReconcileExpiredNativeCampaignAttempt(context.Background(), nativeCampaignLeaseIdentityOf(a))
			results <- err
		}()
	}
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	campaign, err := d.NativeCampaign(context.Background(), a.TaskID, a.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	if campaign.ChargedBudgetMS != a.ReservedBudgetMS {
		t.Fatal("concurrent recovery double charged")
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE task_id=$1 AND attempt_id=$2 AND kind='budget.charged'`, a.TaskID, a.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate settlement event: %d %v", count, err)
	}
}
func TestNativeCampaignRecoveryRechecksLeaseAfterRowLock(t *testing.T) {
	d, a := t5cRecoveryAttempt(t, true)
	t5cExpire(t, d, a)
	tx, err := d.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRowContext(context.Background(), `SELECT id FROM native_campaigns WHERE id=$1 FOR UPDATE`, a.CampaignID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	// Simulate a valid lease authority winning the shared row-lock order after
	// a stale observer read an expired candidate. Recovery must reread it.
	if _, err := tx.ExecContext(context.Background(), `UPDATE native_campaign_attempts SET lease_expires_at=clock_timestamp()+interval '30 seconds' WHERE task_id=$1 AND id=$2`, a.TaskID, a.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := d.ReconcileExpiredNativeCampaignAttempt(context.Background(), nativeCampaignLeaseIdentityOf(a))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("recovery bypassed row lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if NativeCampaignErrorCode(err) != "lease_active" {
			t.Fatalf("stale expiry accepted: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("recovery did not finish after lock release")
	}
	unchanged, err := d.NativeCampaignAttempt(context.Background(), a.TaskID, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.State != a.State || unchanged.ChargedBudgetMS != 0 || !unchanged.ResourceHold {
		t.Fatal("live owner was interrupted")
	}
}
