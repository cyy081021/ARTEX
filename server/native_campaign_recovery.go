package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"time"
)

// Campaign-referenced ledgers belong exclusively to campaign recovery, even
// after an attempt becomes terminal. All unreferenced legacy rows retain the
// previous startup failure semantics. These exact statements are shared with
// startup-ownership regression tests; they never start or clean any resource.
const nativeCampaignLegacyRuntimeStartupSQL = `UPDATE reverse_runtime_runs SET status='failed',last_error='服务中断；自有运行环境的清理需核对，未自动重试',finished_at=now() WHERE status='running' AND NOT EXISTS (SELECT 1 FROM native_campaign_attempts a WHERE a.runtime_run_id=reverse_runtime_runs.id)`
const nativeCampaignLegacyNativeStartupSQL = `UPDATE reverse_native_runs n SET target_state='failed' FROM reverse_runtime_runs r WHERE n.run_id=r.id AND r.status='failed' AND n.target_state IN ('starting','running','stopped') AND NOT EXISTS (SELECT 1 FROM native_campaign_attempts a WHERE a.runtime_run_id=r.id OR a.native_run_id=n.run_id)`

// RetrySealedCleanup consumes only a committed terminal snapshot. It never
// constructs an execution runner or starts/resumes an attempt.
func (m *nativeCampaignManager) RetrySealedCleanup(ctx context.Context, taskID, campaignID, attemptID int64) (*db.NativeCampaignCleanupResult, error) {
	if m == nil || !m.enabled {
		return nil, ErrNativeCampaignDisabled
	}
	if !m.beginOperation() {
		return nil, ErrNativeCampaignManagerClosed
	}
	m.mu.Lock()
	lifecycle := m.ctx
	m.mu.Unlock()
	if lifecycle == nil {
		m.endOperation()
		return nil, errors.New("manager lifecycle unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	limit := m.cleanupTimeout
	if limit <= 0 || limit > 60*time.Second {
		limit = 60 * time.Second
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	stopCancel := context.AfterFunc(lifecycle, cancel)
	type result struct {
		value *db.NativeCampaignCleanupResult
		err   error
	}
	results := make(chan result, 1)
	go func() {
		defer m.endOperation()
		defer stopCancel()
		value, err := m.retrySealedCleanupOwned(cleanupCtx, taskID, campaignID, attemptID)
		results <- result{value, err}
	}()
	select {
	case out := <-results:
		return out.value, out.err
	case <-cleanupCtx.Done():
		return nil, cleanupCtx.Err()
	}
}

func (m *nativeCampaignManager) retrySealedCleanupOwned(cleanupCtx context.Context, taskID, campaignID, attemptID int64) (*db.NativeCampaignCleanupResult, error) {
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrNativeCampaignManagerClosed
	}
	if m.cleanupProbe == nil {
		return nil, errors.New("sealed cleanup probe is not configured")
	}

	started := time.Now()
	snapshot, err := m.pg.NativeCampaignCleanupSnapshot(cleanupCtx, m.service.systemAuthorizer, taskID, campaignID, attemptID)
	if err != nil {
		return nil, err
	}
	attempt := snapshot.Attempt
	plan, err := nativeCampaignPlanFromResources(attempt.OwnedResources)
	if err != nil {
		return nil, err
	}
	if plan == nil || m.runnerStagingRoot == "" || plan.StagingRoot != m.runnerStagingRoot {
		return nil, errors.New("sealed cleanup root is not explicitly configured")
	}
	if err := plan.validate(taskID, campaignID, attemptID, attempt.FencingToken); err != nil {
		return nil, err
	}
	seal, err := nativeCampaignSealFromResources(attempt.OwnedResources)
	if err != nil {
		return nil, err
	}
	if err := seal.validate(plan); err != nil {
		return nil, err
	}
	request := nativeCampaignCleanupRequest{RequestID: fmt.Sprintf("sealed-cleanup-%d-%d", attemptID, snapshot.Campaign.StateVersion), TaskID: taskID, CampaignID: campaignID, AttemptID: attemptID, FencingToken: attempt.FencingToken, ResourcePlan: plan, CreationSeal: seal}
	if err := cleanupCtx.Err(); err != nil {
		return nil, err
	}
	report, err := m.cleanupProbe(cleanupCtx, request)
	if err != nil {
		return nil, err
	}
	if err := cleanupCtx.Err(); err != nil {
		return nil, err
	}
	if !report.verifiedFor(plan, seal) {
		return nil, errors.New("cleanup did not verify the complete sealed resource set")
	}
	// Cancellation may race the callback's return; the same context covers CAS.
	m.mu.Lock()
	closed = m.closed
	m.mu.Unlock()
	if closed {
		return nil, ErrNativeCampaignManagerClosed
	}
	return m.pg.RetryNativeCampaignSealedCleanup(cleanupCtx, m.service.systemAuthorizer, db.NativeCampaignCleanupCommand{TaskID: taskID, CampaignID: campaignID, AttemptID: attemptID, CleanupVerified: true, CleanupElapsedMS: time.Since(started).Milliseconds(), ActorKind: "admin"}, db.NativeCampaignCleanupExpectation{FencingToken: attempt.FencingToken, StateVersion: snapshot.Campaign.StateVersion, OwnedResources: attempt.OwnedResources})
}

// Normal finalization consumes the just-committed immutable DB snapshot, never
// a runner's in-memory seal. The existing run finalizer owns the entire call.
func (m *nativeCampaignManager) cleanupSealedFinal(ctx context.Context, run *nativeCampaignRun, a *db.NativeCampaignAttempt) (*nativeCampaignCleanupReport, error) {
	if m.cleanupProbe == nil {
		return nil, errors.New("sealed cleanup probe is not configured")
	}
	if a == nil || a.TaskID != run.taskID || a.CampaignID != run.campaignID || a.ID != run.attemptID || a.FencingToken != run.fencingToken || a.LeaseOwner != run.leaseOwner || a.LeaseInstance != run.leaseInstance || !a.ResourceHold {
		return nil, errors.New("sealed cleanup snapshot identity mismatch")
	}
	plan, err := nativeCampaignPlanFromResources(a.OwnedResources)
	if err != nil {
		return nil, err
	}
	if plan == nil || m.runnerStagingRoot == "" || plan.StagingRoot != m.runnerStagingRoot {
		return nil, errors.New("sealed cleanup root is not explicitly configured")
	}
	if err = plan.validate(run.taskID, run.campaignID, run.attemptID, run.fencingToken); err != nil {
		return nil, err
	}
	seal, err := nativeCampaignSealFromResources(a.OwnedResources)
	if err != nil {
		return nil, err
	}
	if err = seal.validate(plan); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	started := time.Now()
	report, err := m.cleanupProbe(ctx, nativeCampaignCleanupRequest{RequestID: fmt.Sprintf("final-cleanup-%d-%d", run.attemptID, run.fencingToken), TaskID: run.taskID, CampaignID: run.campaignID, AttemptID: run.attemptID, FencingToken: run.fencingToken, ResourcePlan: plan, CreationSeal: seal})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if !report.verifiedFor(plan, seal) {
		return nil, errors.New("final cleanup did not verify the full durable seal")
	}
	report.ElapsedMS = time.Since(started).Milliseconds()
	return &report, nil
}
