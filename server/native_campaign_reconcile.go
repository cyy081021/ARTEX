package server

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// settleUnsealedCleanup releases the single global worker slot for an attempt whose
// final frame was lost before the creation seal was persisted. Nothing is created,
// adopted or transferred: the caller-side proof is that every planned container is
// already absent and the staging directory is gone, which is exactly what the sealed
// probe would have established. Without this path a lost final keeps the slot held
// forever, because the sealed retry needs a seal that never existed.
func (s *nativeCampaignService) settleUnsealedCleanup(ctx context.Context, taskID, campaignID int64) (*db.NativeCampaignCleanupResult, error) {
	if s == nil || s.pg == nil {
		return nil, nativeCampaignAuthErr("environment_incompatible", 409, "campaign unavailable")
	}
	attempts, err := s.pg.NativeCampaignAttempts(ctx, taskID, campaignID, 50, 0)
	if err != nil {
		return nil, err
	}
	var held *db.NativeCampaignAttempt
	for i := range attempts {
		if attempts[i].ResourceHold && attempts[i].CleanupStatus == "unknown" {
			held = &attempts[i]
			break
		}
	}
	if held == nil {
		return nil, nativeCampaignAuthErr("state_conflict", 409, "no held attempt needs reconciliation")
	}
	plan, err := nativeCampaignPlanFromResources(held.OwnedResources)
	if err != nil {
		return nil, nativeCampaignAuthErr("state_conflict", 409, "owned resource snapshot is invalid")
	}
	if plan == nil {
		return nil, nativeCampaignAuthErr("state_conflict", 409, "attempt has no resource plan")
	}
	started := time.Now()
	absent, err := s.plannedResourcesAbsent(ctx, plan)
	if err != nil {
		return nil, err
	}
	if !absent {
		return nil, nativeCampaignAuthErr("state_conflict", 409, "planned resources are still present; use the sealed cleanup path")
	}
	cmd := db.NativeCampaignCleanupCommand{
		TaskID: taskID, CampaignID: campaignID, AttemptID: held.ID,
		CleanupVerified: true, CleanupElapsedMS: time.Since(started).Milliseconds(),
		ActorKind: "admin",
	}
	return s.pg.SettleUnsealedNativeCampaignCleanup(ctx, s.systemAuthorizer, cmd)
}

// plannedResourcesAbsent reports whether every planned container is gone and the
// staging directory no longer exists. A container is only "absent" when docker cannot
// resolve its own name; anything else is treated as still present.
func (s *nativeCampaignService) plannedResourcesAbsent(ctx context.Context, plan *nativeCampaignResourcePlan) (bool, error) {
	docker := strings.TrimSpace(os.Getenv("ARTEX_NATIVE_CAMPAIGN_DOCKER"))
	if docker == "" || !filepath.IsAbs(docker) {
		return false, nativeCampaignAuthErr("environment_incompatible", 409, "docker executable is not configured")
	}
	if plan == nil || len(plan.ContainerNames) == 0 || plan.StagingRoot == "" || plan.StagingBasename == "" {
		return false, nativeCampaignAuthErr("state_conflict", 409, "resource plan is incomplete")
	}
	for _, name := range plan.ContainerNames {
		probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		out, err := exec.CommandContext(probeCtx, docker, "inspect", "--format", "{{.Id}}", name).CombinedOutput()
		cancel()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return false, nil
		}
	}
	staging := filepath.Join(plan.StagingRoot, plan.StagingBasename)
	if _, err := os.Lstat(staging); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, nativeCampaignAuthErr("state_conflict", 409, "staging directory cannot be inspected")
	}
	return true, nil
}
