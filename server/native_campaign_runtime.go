package server

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/db"
)

type nativeCampaignRuntimeConfig struct {
	Enabled           bool
	Environment       nativeCampaignEnvironmentConfig
	DisableBackground bool // deterministic tests only
}
type nativeCampaignRuntime struct {
	service      *nativeCampaignService
	manager      *nativeCampaignManager
	stopOnCancel func() bool
}

func newNativeCampaignRuntime(ctx context.Context, pg *db.DB, storageRoot string, cfg nativeCampaignRuntimeConfig) (*nativeCampaignRuntime, error) {
	// Feature-off does not inspect paths, open a DB, create directories or spawn.
	if !cfg.Enabled {
		return nil, nil
	}
	if pg == nil {
		return nil, errors.New("campaign runtime requires a database")
	}
	environment, err := newNativeCampaignEnvironment(cfg.Environment)
	if err != nil {
		return nil, err
	}
	root, err := filepath.Abs(storageRoot)
	if err != nil {
		return nil, err
	}
	storage, err := newNativeCampaignLocalStorage(root)
	if err != nil {
		return nil, err
	}
	checkpoint, err := newNativeCampaignCheckpointStore(pg, root)
	if err != nil {
		return nil, err
	}
	service, err := newNativeCampaignService(nativeCampaignServiceConfig{Enabled: true, DB: pg, Storage: storage, ImageResolver: environment, CheckpointValidator: checkpoint, CheckpointSink: checkpoint})
	if err != nil {
		return nil, err
	}
	process := environment.processConfig()
	manager, err := newNativeCampaignManager(nativeCampaignManagerConfig{Enabled: true, DB: pg, Service: service, RunnerFactory: newNativeCampaignProcessFactory(process), CleanupProbe: newNativeCampaignCleanupProbe(process), RunnerStagingRoot: environment.config.StagingRoot, DisableBackground: cfg.DisableBackground})
	if err != nil {
		return nil, err
	}
	r := &nativeCampaignRuntime{service: service, manager: manager}
	// The same manager survives a conservative startup-reconciliation error so
	// explicit cleanup remains available. No replacement owner is constructed.
	r.stopOnCancel = context.AfterFunc(ctx, func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := manager.Close(closeCtx); err != nil {
			log.Printf("[native campaign] shutdown retained unresolved ownership: %v", err)
		}
	})
	return r, manager.Start(ctx)
}
func (r *nativeCampaignRuntime) close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.stopOnCancel != nil {
		r.stopOnCancel()
	}
	return r.manager.Close(ctx)
}
func (s *Server) initNativeCampaign() error {
	s.campaignOnce.Do(func() {
		if !nativeCampaignFeatureEnabled() {
			return
		}
		cfg := nativeCampaignRuntimeConfig{Enabled: true, Environment: nativeCampaignEnvironmentConfig{Python: os.Getenv("ARTEX_NATIVE_CAMPAIGN_PYTHON"), ModuleRoot: os.Getenv("ARTEX_NATIVE_CAMPAIGN_MODULE_ROOT"), Docker: os.Getenv("ARTEX_NATIVE_CAMPAIGN_DOCKER"), StagingRoot: os.Getenv("ARTEX_NATIVE_CAMPAIGN_STAGING_ROOT"), DockerConfigDir: os.Getenv("ARTEX_NATIVE_CAMPAIGN_DOCKER_CONFIG")}}
		s.campaign, s.campaignInitErr = newNativeCampaignRuntime(s.ctx, s.m.pg, s.m.dir, cfg)
	})
	return s.campaignInitErr
}

// Close joins Campaign ownership before the caller closes the shared DB. A
// timeout is an explicit failure, never a claim that resources were cleaned.
func (s *Server) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.campaign.close(ctx)
}

// campaignService returns the initialized campaign service, or nil when the feature is
// not configured on this server. Tool wiring uses it to decide whether the durable
// campaign surface exists at all; a nil service keeps the tool out of the list.
func (s *Server) campaignService() *nativeCampaignService {
	if s == nil || s.campaign == nil {
		return nil
	}
	return s.campaign.service
}
