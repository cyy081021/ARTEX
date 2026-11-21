package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

// Native Campaign v1 (T4a) internal service.
//
// The service is shared by the single-worker manager and the bounded admin HTTP
// surface. Tools remain unregistered; runtime construction is explicitly gated
// and default-off. Reads never initialize or start a runtime.
var (
	ErrNativeCampaignDisabled               = errors.New("native campaign is disabled (ARTEX_NATIVE_CAMPAIGN)")
	ErrNativeCampaignReconciliationRequired = errors.New("native campaign reconciliation required before scheduling")
)

// nativeCampaignFeatureEnabled is the default-off gate. The manager/service must
// also be constructed with Enabled=true to run; an environment value alone never
// starts anything. Tests can exercise both states without a server.
func nativeCampaignFeatureEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_NATIVE_CAMPAIGN"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

type nativeCampaignClock interface {
	Now() time.Time
}

type nativeCampaignSystemClock struct{}

func (nativeCampaignSystemClock) Now() time.Time { return time.Now() }

// nativeCampaignStorage is the required artifact/evidence boundary. It is an
// interface because T4a must not pretend file/object persistence exists yet. A
// nil storage or any error is fail-closed.
type nativeCampaignStorage interface {
	VerifyArtifact(ctx context.Context, taskID int64, artifact *db.ReverseArtifact) error
	PersistEvidence(ctx context.Context, in nativeCampaignEvidenceWrite) (*nativeCampaignEvidenceRef, error)
}

type nativeCampaignEvidenceWrite struct {
	TaskID      int64
	CampaignID  int64
	AttemptID   int64
	Kind        string
	Operation   string
	Authority   string
	Observation json.RawMessage
}

type nativeCampaignEvidenceRef struct {
	ResultPath  string
	SHA256      string
	Observation json.RawMessage
	Truncated   bool
}

// nativeCampaignImageResolver must confirm the actual immutable image id. T4a
// does not inspect Docker itself; without a resolver every start/resume/claim is
// rejected instead of assuming the declared digest is the real image.
type nativeCampaignImageResolver interface {
	ResolveImageID(ctx context.Context, profile reverseRuntimeProfile, declaredDigest string) (string, error)
}

// nativeCampaignCheckpointValidator is required whenever a resume/final relies
// on checkpoint content. T5 owns the actual manifest/object verification.
type nativeCampaignCheckpointValidator interface {
	ValidateCheckpoint(ctx context.Context, taskID, campaignID, checkpointID int64) error
}

// A validator without this capability can preflight metadata but cannot launch
// a restored attempt. The concrete store uses one loader for both operations.
type nativeCampaignCheckpointLoader interface {
	LoadCheckpoint(ctx context.Context, taskID, campaignID, checkpointID int64) (*nativeCampaignCheckpointRestore, error)
}

// nativeCampaignCheckpointSink persists a final checkpoint and returns the
// already-verified DB row. T5 owns the file/manifest implementation. A paused
// final without a configured sink fails closed.
type nativeCampaignCheckpointSink interface {
	PersistCheckpoint(ctx context.Context, in nativeCampaignCheckpointWrite) (*db.NativeCampaignCheckpoint, error)
}

type nativeCampaignCheckpointWrite struct {
	Identity   db.NativeCampaignLeaseIdentity
	Corpus     []nativeCampaignCheckpointRecord
	TaskID     int64
	CampaignID int64
	AttemptID  int64
	Final      nativeCampaignRunnerCheckpoint
}

type nativeCampaignServiceConfig struct {
	Enabled             bool
	DB                  *db.DB
	Clock               nativeCampaignClock
	Profiles            func() ([]reverseRuntimeProfile, error)
	Storage             nativeCampaignStorage
	ImageResolver       nativeCampaignImageResolver
	CheckpointValidator nativeCampaignCheckpointValidator
	CheckpointSink      nativeCampaignCheckpointSink
}

type nativeCampaignService struct {
	enabled        bool
	pg             *db.DB
	clock          nativeCampaignClock
	profiles       func() ([]reverseRuntimeProfile, error)
	storage        nativeCampaignStorage
	images         nativeCampaignImageResolver
	checkpoints    nativeCampaignCheckpointValidator
	checkpointSink nativeCampaignCheckpointSink
	// beforeStateMutation is an internal deterministic-test hook used to force
	// a real state_version conflict between service load and T3 CAS. It is never
	// set in production.
	beforeStateMutation func()
}

func newNativeCampaignService(cfg nativeCampaignServiceConfig) (*nativeCampaignService, error) {
	if cfg.DB == nil {
		return nil, errors.New("native campaign service requires a database")
	}
	if cfg.Clock == nil {
		cfg.Clock = nativeCampaignSystemClock{}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = reverseRuntimeProfiles
	}
	return &nativeCampaignService{
		enabled: cfg.Enabled, pg: cfg.DB, clock: cfg.Clock, profiles: cfg.Profiles,
		storage: cfg.Storage, images: cfg.ImageResolver,
		checkpoints: cfg.CheckpointValidator, checkpointSink: cfg.CheckpointSink,
	}, nil
}

func (s *nativeCampaignService) requireEnabled() error {
	if s == nil || !s.enabled {
		return ErrNativeCampaignDisabled
	}
	return nil
}

type nativeCampaignTaskView struct {
	ID       int64
	Kind     string
	Status   string
	Paused   bool
	Deleted  bool
	Archived bool
}

type nativeCampaignAuthorization struct {
	Campaign             *db.NativeCampaign
	Task                 *nativeCampaignTaskView
	Artifact             *db.ReverseArtifact
	Profile              reverseRuntimeProfile
	Policy               db.ReverseRuntimePolicy
	ImageID              string
	CheckpointID         *int64
	ProfileMaxDurationMS int64
	PolicyMaxDurationMS  int64
	RequestedBudgetMS    int64
}

func nativeCampaignAuthErr(code string, status int, format string, args ...any) *db.NativeCampaignError {
	return &db.NativeCampaignError{Code: code, Status: status, Message: fmt.Sprintf(format, args...)}
}

type nativeCampaignStateCommand struct {
	TaskID               int64
	CampaignID           int64
	RequestID            string
	ExpectedStateVersion int64
	AttemptBudgetMS      *int64
	Reason               string
	ActorKind            string
	ActorID              int64
}

type nativeCampaignClaimOutcome struct {
	Claim *db.NativeCampaignClaimResult
	Auth  *nativeCampaignAuthorization
}

func (s *nativeCampaignService) loadCampaign(ctx context.Context, taskID, campaignID int64) (*db.NativeCampaign, error) {
	if taskID <= 0 || campaignID <= 0 {
		return nil, nativeCampaignAuthErr("invalid_request", 400, "task_id and campaign_id are required")
	}
	campaign, err := s.pg.NativeCampaign(ctx, taskID, campaignID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignAuthErr("not_found", 404, "campaign does not belong to the task")
	}
	if err != nil {
		return nil, nativeCampaignAuthErr("internal", 500, "read campaign: %v", err)
	}
	return campaign, nil
}

func (s *nativeCampaignService) loadTask(ctx context.Context, taskID int64) (*nativeCampaignTaskView, error) {
	var task nativeCampaignTaskView
	err := s.pg.QueryRowContext(ctx, `SELECT id,kind,status,paused,
		deleted_at IS NOT NULL,archived_at IS NOT NULL FROM tasks WHERE id=$1`, taskID).
		Scan(&task.ID, &task.Kind, &task.Status, &task.Paused, &task.Deleted, &task.Archived)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "task is missing or deleted")
	}
	if err != nil {
		return nil, nativeCampaignAuthErr("internal", 500, "read task authorization: %v", err)
	}
	return &task, nil
}

func (s *nativeCampaignService) checkIntent(ctx context.Context, taskID, intentID int64) error {
	if intentID <= 0 {
		return nativeCampaignAuthErr("authorization_revoked", 403, "intent id is required")
	}
	var state, role string
	err := s.pg.QueryRowContext(ctx, `SELECT n.state,
		COALESCE(n.payload->'contract'->>'execution_role','')
		FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
		WHERE n.id=$1 AND t.id=$2 AND n.kind='intent'`, intentID, taskID).Scan(&state, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return nativeCampaignAuthErr("authorization_revoked", 403, "intent does not belong to the task")
	}
	if err != nil {
		return nativeCampaignAuthErr("internal", 500, "read intent authorization: %v", err)
	}
	if state != "running" {
		return nativeCampaignAuthErr("authorization_revoked", 403, "intent is not running")
	}
	if role != "reverse_dynamic" {
		return nativeCampaignAuthErr("authorization_revoked", 403, "intent is not a reverse_dynamic operator")
	}
	return nil
}

func (s *nativeCampaignService) checkActors(ctx context.Context, campaign *db.NativeCampaign, actorKind string, actorID int64) error {
	if actorKind == "" {
		actorKind = "admin"
	}
	switch actorKind {
	case "admin":
		if actorID != 0 {
			return nativeCampaignAuthErr("authorization_revoked", 403, "admin actor must not carry an intent id")
		}
	case "intent":
		if err := s.checkIntent(ctx, campaign.TaskID, actorID); err != nil {
			return err
		}
	default:
		return nativeCampaignAuthErr("authorization_revoked", 403, "unsupported operator kind")
	}
	if campaign.CreatorKind == "intent" {
		if err := s.checkIntent(ctx, campaign.TaskID, campaign.CreatorID); err != nil {
			return nativeCampaignAuthErr("authorization_revoked", 403, "campaign creator intent is no longer authorized")
		}
	}
	return nil
}

func nativeCampaignSpecString(spec json.RawMessage, key string) (string, bool, error) {
	if len(spec) == 0 {
		return "", false, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(spec, &fields); err != nil {
		return "", false, nativeCampaignAuthErr("invalid_request", 400, "campaign spec is not an object")
	}
	raw, ok := fields[key]
	if !ok {
		return "", false, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false, nativeCampaignAuthErr("environment_incompatible", 409, "spec %s must be a string", key)
	}
	return value, true, nil
}

func (s *nativeCampaignService) checkArtifact(ctx context.Context, campaign *db.NativeCampaign) (*db.ReverseArtifact, error) {
	artifact, err := s.pg.GetReverseArtifact(campaign.TaskID, campaign.ArtifactID)
	if err != nil {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "artifact does not belong to the task")
	}
	if artifact == nil {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "artifact does not belong to the task")
	}
	if artifact.SHA256 != campaign.ArtifactSHA256 {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "artifact hash no longer matches the campaign binding")
	}
	if specHash, ok, err := nativeCampaignSpecString(campaign.Spec, "artifact_sha256"); err != nil {
		return nil, err
	} else if ok && specHash != campaign.ArtifactSHA256 {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "spec artifact_sha256 does not match the task artifact")
	}
	if s.storage == nil {
		return nil, nativeCampaignAuthErr("environment_incompatible", 409, "artifact storage verifier is not configured")
	}
	if err := s.storage.VerifyArtifact(ctx, campaign.TaskID, artifact); err != nil {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "artifact file failed verification: %v", err)
	}
	return artifact, nil
}

func (s *nativeCampaignService) findProfile(profileID string) (reverseRuntimeProfile, error) {
	if s.profiles == nil {
		return reverseRuntimeProfile{}, nativeCampaignAuthErr("environment_incompatible", 409, "profile source is not configured")
	}
	profiles, err := s.profiles()
	if err != nil {
		return reverseRuntimeProfile{}, nativeCampaignAuthErr("environment_incompatible", 409, "runtime profiles are unreadable")
	}
	for _, profile := range profiles {
		if profile.ID == profileID {
			return profile, nil
		}
	}
	return reverseRuntimeProfile{}, nativeCampaignAuthErr("authorization_revoked", 403, "profile is not configured or no longer authorized")
}

func validResolvedImageID(imageID string) bool {
	if len(imageID) != len("sha256:")+64 || !strings.HasPrefix(imageID, "sha256:") {
		return false
	}
	return db.NativeSHA256(imageID[len("sha256:"):])
}

func (s *nativeCampaignService) checkProfileAndImage(ctx context.Context, campaign *db.NativeCampaign) (reverseRuntimeProfile, string, error) {
	profile, err := s.findProfile(campaign.ProfileID)
	if err != nil {
		return reverseRuntimeProfile{}, "", err
	}
	if _, err := validateFuzzProfile(profile); err != nil {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("authorization_revoked", 403, "profile is not enabled for fuzzing: %v", err)
	}
	imageDigest, _ := profile.Settings["image"].(string)
	if imageDigest != campaign.ImageDigest {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "profile image digest does not match the campaign binding")
	}
	if specImage, ok, err := nativeCampaignSpecString(campaign.Spec, "image"); err != nil {
		return reverseRuntimeProfile{}, "", err
	} else if ok && specImage != campaign.ImageDigest {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "spec image does not match the campaign image digest")
	}
	if s.images == nil {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "actual image id validator is not configured")
	}
	resolved, err := s.images.ResolveImageID(ctx, profile, campaign.ImageDigest)
	if err != nil {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "actual image id cannot be confirmed: %v", err)
	}
	if !validResolvedImageID(resolved) {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "image resolver returned an invalid immutable image id")
	}
	if campaign.ImageID != nil && *campaign.ImageID != "" && *campaign.ImageID != resolved {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "actual image id changed since the previous attempt")
	}
	if specImageID, ok, err := nativeCampaignSpecString(campaign.Spec, "image_id"); err != nil {
		return reverseRuntimeProfile{}, "", err
	} else if ok && specImageID != "" && specImageID != resolved {
		return reverseRuntimeProfile{}, "", nativeCampaignAuthErr("environment_incompatible", 409, "spec image_id does not match the actual image")
	}
	return profile, resolved, nil
}

func nativeCampaignStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func nativeCampaignInt64SliceContains(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func (s *nativeCampaignService) checkPolicy(ctx context.Context, campaign *db.NativeCampaign) (db.ReverseRuntimePolicy, error) {
	policy, err := s.pg.ReverseRuntimePolicy(campaign.TaskID)
	if err != nil {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("authorization_revoked", 403, "runtime policy is unreadable")
	}
	if !policy.Enabled {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("authorization_revoked", 403, "runtime policy is disabled")
	}
	if policy.Revision != campaign.PolicyRevision {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("authorization_revoked", 403, "runtime policy revision changed")
	}
	if !nativeCampaignStringSliceContains(policy.ProfileIDs, campaign.ProfileID) {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("authorization_revoked", 403, "profile is no longer in the runtime authorization list")
	}
	if !nativeCampaignInt64SliceContains(policy.ArtifactIDs, campaign.ArtifactID) {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("authorization_revoked", 403, "artifact is no longer in the runtime authorization list")
	}
	if policy.MaxDurationMS < int(db.NativeCampaignMinExecutionMS) || policy.MaxDurationMS > 900000 {
		return db.ReverseRuntimePolicy{}, nativeCampaignAuthErr("environment_incompatible", 409, "runtime policy duration is outside the supported window")
	}
	return policy, nil
}

func (s *nativeCampaignService) checkConfig(ctx context.Context, campaign *db.NativeCampaign) error {
	var revision int64
	err := s.pg.QueryRowContext(ctx,
		`SELECT revision FROM reverse_native_configs WHERE task_id=$1`, campaign.TaskID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return nativeCampaignAuthErr("environment_incompatible", 409, "native analysis configuration is missing")
	}
	if err != nil {
		return nativeCampaignAuthErr("internal", 500, "read native configuration revision: %v", err)
	}
	if revision != campaign.ConfigRevision {
		return nativeCampaignAuthErr("environment_incompatible", 409, "native configuration revision changed")
	}
	return nil
}

// nativeCampaignDurableBudgetCap reads the latest explicit start/resume budget
// authorization from the existing append-only event stream. A nil result means
// the operator omitted the value, so the immutable spec default applies.
func (s *nativeCampaignService) nativeCampaignDurableBudgetCap(ctx context.Context, taskID, campaignID int64) (*int64, error) {
	var raw []byte
	err := s.pg.QueryRowContext(ctx, `SELECT payload FROM native_campaign_events
		WHERE task_id=$1 AND campaign_id=$2
		  AND kind IN ('campaign.queued','campaign.resume_queued')
		ORDER BY id DESC LIMIT 1`, taskID, campaignID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, nativeCampaignAuthErr("internal", 500, "read attempt budget authorization: %v", err)
	}
	var payload struct {
		AttemptBudgetMS *int64 `json:"attempt_budget_ms"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, nativeCampaignAuthErr("invalid_request", 400, "attempt budget authorization is malformed")
	}
	return payload.AttemptBudgetMS, nil
}

// nativeCampaignRequestedBudget resolves the authorization for one action.
//
// A mutation that queues a new attempt (start on draft, resume) must not inherit
// the previous attempt's explicit cap: when the operator omits attempt_budget_ms
// the immutable spec default is the sole authorization. Only the scheduler
// claim (and a no-op start on an already queued campaign) reads the cap persisted
// on the current queued event. This is what lets a resume whose previous cap is
// larger than the remaining budget succeed with a smaller durable spec default.
func (s *nativeCampaignService) nativeCampaignRequestedBudget(ctx context.Context, campaign *db.NativeCampaign, explicit *int64, useCurrentQueuedCap bool) (int64, error) {
	remaining := campaign.TotalBudgetMS - campaign.ChargedBudgetMS
	if remaining < db.NativeCampaignMinAttemptBudgetMS {
		return 0, nativeCampaignAuthErr("budget_exhausted", 409, "remaining campaign budget is below the 6000ms minimum")
	}
	if explicit != nil {
		if *explicit < db.NativeCampaignMinAttemptBudgetMS || *explicit > db.NativeCampaignMaxAttemptBudgetMS {
			return 0, nativeCampaignAuthErr("invalid_request", 400, "attempt_budget_ms must be between 6000 and 900000")
		}
		if *explicit > remaining {
			return 0, nativeCampaignAuthErr("budget_exhausted", 409, "attempt_budget_ms exceeds the remaining campaign budget")
		}
		return *explicit, nil
	}
	if useCurrentQueuedCap {
		// The current queued start/resume event is the authorization for the
		// attempt the scheduler is about to claim.
		durableCap, err := s.nativeCampaignDurableBudgetCap(ctx, campaign.TaskID, campaign.ID)
		if err != nil {
			return 0, err
		}
		if durableCap != nil {
			if *durableCap < db.NativeCampaignMinAttemptBudgetMS || *durableCap > db.NativeCampaignMaxAttemptBudgetMS {
				return 0, nativeCampaignAuthErr("invalid_request", 400, "persisted attempt budget cap is invalid")
			}
			if *durableCap > remaining {
				return 0, nativeCampaignAuthErr("budget_exhausted", 409, "persisted attempt budget cap exceeds the remaining campaign budget")
			}
			return *durableCap, nil
		}
	}
	// No explicit cap (and no current queued cap to reuse): mirror T3's single
	// durable default source exactly. A spec default wins but is clamped by
	// remaining; legacy specs use 60000 clamped by remaining.
	if len(campaign.Spec) > 0 {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(campaign.Spec, &fields); err == nil {
			if raw, ok := fields["default_attempt_budget_ms"]; ok {
				value, err := db.ParseNativeCampaignBudgetMS(raw)
				if err != nil || value < db.NativeCampaignMinAttemptBudgetMS || value > db.NativeCampaignMaxAttemptBudgetMS {
					return 0, nativeCampaignAuthErr("invalid_request", 400, "spec default_attempt_budget_ms is invalid")
				}
				if value < remaining {
					return value, nil
				}
				return remaining, nil
			}
		}
	}
	requested := int64(db.NativeCampaignCompatDefaultAttemptBudgetMS)
	if remaining < requested {
		requested = remaining
	}
	return requested, nil
}

func (s *nativeCampaignService) checkBudget(ctx context.Context, campaign *db.NativeCampaign, explicit *int64, useCurrentQueuedCap bool, profileMax, policyMax int64) (int64, error) {
	requested, err := s.nativeCampaignRequestedBudget(ctx, campaign, explicit, useCurrentQueuedCap)
	if err != nil {
		return 0, err
	}
	execution := requested - db.NativeCampaignOverheadReserveMS
	if profileMax > 0 && profileMax < execution {
		execution = profileMax
	}
	if policyMax > 0 && policyMax < execution {
		execution = policyMax
	}
	if execution < db.NativeCampaignMinExecutionMS {
		return 0, nativeCampaignAuthErr("environment_incompatible", 409, "authorized execution window is below 1000ms")
	}
	return requested, nil
}

func (s *nativeCampaignService) checkCheckpoint(ctx context.Context, campaign *db.NativeCampaign) (*int64, error) {
	if campaign.LatestCheckpointID == nil {
		if campaign.State == "paused" {
			emptyPause := campaign.CurrentAttemptID == nil && campaign.CleanupStatus == "not_required" &&
				campaign.PauseOrigin == "queued"
			if !emptyPause {
				return nil, nativeCampaignAuthErr("resume_blocked", 409, "paused campaign has no checkpoint")
			}
		}
		return nil, nil
	}
	checkpoint, err := s.pg.NativeCampaignCheckpoint(ctx, campaign.TaskID, *campaign.LatestCheckpointID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nativeCampaignAuthErr("resume_blocked", 409, "checkpoint does not belong to the campaign")
	}
	if err != nil {
		return nil, nativeCampaignAuthErr("internal", 500, "read checkpoint: %v", err)
	}
	if checkpoint.CampaignID != campaign.ID || checkpoint.State != "verified" {
		return nil, nativeCampaignAuthErr("resume_blocked", 409, "checkpoint is not verified for this campaign")
	}
	if s.checkpoints == nil {
		return nil, nativeCampaignAuthErr("resume_blocked", 409, "checkpoint content validator is not configured")
	}
	if err := s.checkpoints.ValidateCheckpoint(ctx, campaign.TaskID, campaign.ID, checkpoint.ID); err != nil {
		return nil, nativeCampaignAuthErr("resume_blocked", 409, "checkpoint content cannot be verified: %v", err)
	}
	id := checkpoint.ID
	return &id, nil
}

func (s *nativeCampaignService) authorize(ctx context.Context, campaign *db.NativeCampaign, action, actorKind string, actorID int64, budget *int64) (*nativeCampaignAuthorization, error) {
	restored, restoreErr := s.pg.NativeCampaignArchiveRestored(ctx, campaign.TaskID, campaign.ID)
	if restoreErr != nil {
		return nil, restoreErr
	}
	if restored {
		return nil, nativeCampaignAuthErr("archive_restore_not_executable", 409, "restored campaign is not executable")
	}
	task, err := s.loadTask(ctx, campaign.TaskID)
	if err != nil {
		return nil, err
	}
	if task.Kind != "reverse" {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "campaign requires a reverse task")
	}
	if task.Deleted || task.Archived {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "task is deleted or archived")
	}
	if db.IsTerminal(task.Status) {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "task is terminal")
	}
	if task.Paused {
		return nil, nativeCampaignAuthErr("authorization_revoked", 403, "task is paused")
	}
	if err := s.checkActors(ctx, campaign, actorKind, actorID); err != nil {
		return nil, err
	}
	artifact, err := s.checkArtifact(ctx, campaign)
	if err != nil {
		return nil, err
	}
	profile, imageID, err := s.checkProfileAndImage(ctx, campaign)
	if err != nil {
		return nil, err
	}
	profileMax, _ := validateFuzzProfile(profile)
	policy, err := s.checkPolicy(ctx, campaign)
	if err != nil {
		return nil, err
	}
	if err := s.checkConfig(ctx, campaign); err != nil {
		return nil, err
	}
	// A start on a draft or a resume queues a new attempt, so an omitted budget
	// must use the immutable spec default. Only the claim (and the idempotent
	// start of an already queued campaign) reads the cap persisted on the
	// current queued event.
	useCurrentQueuedCap := action == "claim" || (action == "start" && campaign.State == "queued")
	requested, err := s.checkBudget(ctx, campaign, budget, useCurrentQueuedCap, int64(profileMax), int64(policy.MaxDurationMS))
	if err != nil {
		return nil, err
	}
	if action == "resume" {
		if campaign.CleanupStatus != "not_required" && campaign.CleanupStatus != "verified" {
			return nil, nativeCampaignAuthErr("cleanup_unknown", 503, "campaign cleanup is not verified")
		}
	}
	checkpointID, err := s.checkCheckpoint(ctx, campaign)
	if err != nil {
		return nil, err
	}
	return &nativeCampaignAuthorization{
		Campaign: campaign, Task: task, Artifact: artifact, Profile: profile,
		Policy: policy, ImageID: imageID, CheckpointID: checkpointID,
		ProfileMaxDurationMS: int64(profileMax), PolicyMaxDurationMS: int64(policy.MaxDurationMS),
		RequestedBudgetMS: requested,
	}, nil
}

func (s *nativeCampaignService) validationAuthorizer(action, actorKind string, actorID int64, budget *int64) db.NativeCampaignAuthorizer {
	return func(ctx context.Context, req db.NativeCampaignAuthorizationRequest) error {
		campaign, err := s.loadCampaign(ctx, req.TaskID, req.CampaignID)
		if err != nil {
			return err
		}
		_, err = s.authorize(ctx, campaign, action, actorKind, actorID, budget)
		return err
	}
}

// Start re-validates every durable authorization item and then only queues the
// campaign through the T3 state machine. It never claims or starts a runner.
func (s *nativeCampaignService) Start(ctx context.Context, cmd nativeCampaignStateCommand) (*db.NativeCampaignCommandResponse, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, cmd.TaskID, cmd.CampaignID)
	if err != nil {
		return nil, err
	}
	if _, err := s.authorize(ctx, campaign, "start", cmd.ActorKind, cmd.ActorID, cmd.AttemptBudgetMS); err != nil {
		return nil, err
	}
	return s.pg.StartNativeCampaign(ctx, s.validationAuthorizer("start", cmd.ActorKind, cmd.ActorID, cmd.AttemptBudgetMS),
		db.NativeCampaignStateCommand{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, RequestID: cmd.RequestID,
			ExpectedStateVersion: cmd.ExpectedStateVersion, AttemptBudgetMS: cmd.AttemptBudgetMS,
			ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
		})
}

// Resume has the same authorization contract as start plus checkpoint/content
// verification. It only queues; the manager creates the new Attempt.
func (s *nativeCampaignService) Resume(ctx context.Context, cmd nativeCampaignStateCommand) (*db.NativeCampaignCommandResponse, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, cmd.TaskID, cmd.CampaignID)
	if err != nil {
		return nil, err
	}
	if _, err := s.authorize(ctx, campaign, "resume", cmd.ActorKind, cmd.ActorID, cmd.AttemptBudgetMS); err != nil {
		return nil, err
	}
	return s.pg.ResumeNativeCampaign(ctx, s.validationAuthorizer("resume", cmd.ActorKind, cmd.ActorID, cmd.AttemptBudgetMS),
		db.NativeCampaignStateCommand{
			TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, RequestID: cmd.RequestID,
			ExpectedStateVersion: cmd.ExpectedStateVersion, AttemptBudgetMS: cmd.AttemptBudgetMS,
			Reason: cmd.Reason, ActorKind: cmd.ActorKind, ActorID: cmd.ActorID,
		})
}

func (s *nativeCampaignService) claimActor(campaign *db.NativeCampaign) (string, int64) {
	if campaign.CreatorKind == "intent" {
		return "intent", campaign.CreatorID
	}
	return "admin", 0
}

// Claim re-validates authorization and delegates to the T3 fenced claim. The
// manager never supplies an attempt budget: the durable spec/start-resume cap is
// the only source. A successful claim commits before any runner factory call.
func (s *nativeCampaignService) Claim(ctx context.Context, taskID, campaignID int64, leaseInstance string) (*nativeCampaignClaimOutcome, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	actorKind, actorID := s.claimActor(campaign)
	auth, err := s.authorize(ctx, campaign, "claim", actorKind, actorID, nil)
	if err != nil {
		return nil, err
	}
	claim, err := s.pg.ClaimNativeCampaignAttempt(ctx, s.validationAuthorizer("claim", actorKind, actorID, nil),
		db.NativeCampaignClaimCommand{
			TaskID: taskID, CampaignID: campaignID, LeaseInstance: leaseInstance,
			LeaseMS:              db.NativeCampaignDefaultLeaseMS,
			ProfileMaxDurationMS: auth.ProfileMaxDurationMS, PolicyMaxDurationMS: auth.PolicyMaxDurationMS,
			OperatorKind: actorKind, OperatorID: actorID, ImageID: auth.ImageID,
			ActorKind: actorKind, ActorID: actorID,
		})
	if err != nil {
		return nil, err
	}
	return &nativeCampaignClaimOutcome{Claim: claim, Auth: auth}, nil
}

// AuthorizeClaimAfterClaim is the re-check in the gap between a committed claim
// and runner start. If it fails, the manager must not start the factory.
func (s *nativeCampaignService) AuthorizeClaimAfterClaim(ctx context.Context, taskID, campaignID int64, expectedImageID string) (*nativeCampaignAuthorization, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	actorKind, actorID := s.claimActor(campaign)
	auth, err := s.authorize(ctx, campaign, "claim", actorKind, actorID, nil)
	if err != nil {
		return nil, err
	}
	if expectedImageID != "" && auth.ImageID != expectedImageID {
		return nil, nativeCampaignAuthErr("environment_incompatible", 409, "actual image id changed before runner start")
	}
	return auth, nil
}

func (s *nativeCampaignService) systemAuthorizer(ctx context.Context, req db.NativeCampaignAuthorizationRequest) error {
	switch req.Action {
	case "pause", "cancel", "finalize", "cleanup_retry", "claim", "start", "resume":
	default:
		return nativeCampaignAuthErr("authorization_revoked", 403, "unsupported internal campaign action")
	}
	var exists bool
	if err := s.pg.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM native_campaigns WHERE task_id=$1 AND id=$2)`,
		req.TaskID, req.CampaignID).Scan(&exists); err != nil {
		return nativeCampaignAuthErr("internal", 500, "read campaign ownership: %v", err)
	}
	if !exists {
		return nativeCampaignAuthErr("authorization_revoked", 403, "campaign does not belong to the task")
	}
	return nil
}

// Pause/Cancel are internal watcher transitions. They use a scoped internal
// authorizer after the manager has already made the revocation decision, so a
// revoked intent/task can still be cancelled.
func (s *nativeCampaignService) Pause(ctx context.Context, taskID, campaignID int64, reason, requestID string) (*db.NativeCampaignCommandResponse, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	if s.beforeStateMutation != nil {
		s.beforeStateMutation()
	}
	return s.pg.PauseNativeCampaign(ctx, s.systemAuthorizer, db.NativeCampaignStateCommand{
		TaskID: taskID, CampaignID: campaignID, RequestID: requestID,
		ExpectedStateVersion: campaign.StateVersion, Reason: reason,
		ActorKind: "admin",
	})
}

func (s *nativeCampaignService) Cancel(ctx context.Context, taskID, campaignID int64, reason, requestID string) (*db.NativeCampaignCommandResponse, error) {
	if err := s.requireEnabled(); err != nil {
		return nil, err
	}
	campaign, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	if s.beforeStateMutation != nil {
		s.beforeStateMutation()
	}
	return s.pg.CancelNativeCampaign(ctx, s.systemAuthorizer, db.NativeCampaignStateCommand{
		TaskID: taskID, CampaignID: campaignID, RequestID: requestID,
		ExpectedStateVersion: campaign.StateVersion, Reason: reason,
		ActorKind: "admin",
	})
}

func (s *nativeCampaignService) Finalize(ctx context.Context, cmd db.NativeCampaignFinalizeCommand) (*db.NativeCampaignFinalizeResult, error) {
	return s.pg.FinalizeNativeCampaignAttempt(ctx, s.systemAuthorizer, cmd)
}

func (s *nativeCampaignService) RetryCleanup(ctx context.Context, cmd db.NativeCampaignCleanupCommand) (*db.NativeCampaignCleanupResult, error) {
	return s.pg.RetryNativeCampaignCleanup(ctx, s.systemAuthorizer, cmd)
}

type nativeCampaignMonitorSignal struct {
	Action string
	Reason string
}

func nativeCampaignMonitorSignalOf(action, reason string) nativeCampaignMonitorSignal {
	return nativeCampaignMonitorSignal{Action: action, Reason: reason}
}

// MonitorCampaign evaluates the 1s watcher contract. It never resumes a paused
// campaign and never treats a missing/expired JWT as resource revocation.
func (s *nativeCampaignService) MonitorCampaign(ctx context.Context, taskID, campaignID int64, operatorKind string, operatorID int64) (nativeCampaignMonitorSignal, error) {
	campaign, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nativeCampaignMonitorSignalOf("cancel", "campaign_missing"), nil
	}
	if campaign.DesiredState == "cancelled" {
		return nativeCampaignMonitorSignalOf("cancel", "desired_cancelled"), nil
	}
	task, err := s.loadTask(ctx, taskID)
	if err != nil || task.Deleted || task.Archived || db.IsTerminal(task.Status) {
		return nativeCampaignMonitorSignalOf("cancel", "task_revoked"), nil
	}
	if task.Paused {
		return nativeCampaignMonitorSignalOf("pause", "task_paused"), nil
	}
	if campaign.State != "running" && campaign.State != "stopping" {
		return nativeCampaignMonitorSignalOf("cancel", "campaign_not_running"), nil
	}
	profile, err := s.findProfile(campaign.ProfileID)
	if err != nil {
		return nativeCampaignMonitorSignalOf("pause", "profile_unavailable"), nil
	}
	if profile.Settings["enabled"] == false || profile.Settings["fuzz_enabled"] != true {
		return nativeCampaignMonitorSignalOf("pause", "profile_disabled"), nil
	}
	imageDigest, _ := profile.Settings["image"].(string)
	if imageDigest != campaign.ImageDigest {
		return nativeCampaignMonitorSignalOf("cancel", "image_binding_changed"), nil
	}
	if s.images == nil {
		return nativeCampaignMonitorSignalOf("cancel", "image_validator_missing"), nil
	}
	imageID, err := s.images.ResolveImageID(ctx, profile, campaign.ImageDigest)
	if err != nil || (campaign.ImageID != nil && *campaign.ImageID != "" && *campaign.ImageID != imageID) {
		return nativeCampaignMonitorSignalOf("cancel", "image_changed"), nil
	}
	policy, err := s.pg.ReverseRuntimePolicy(taskID)
	if err != nil || !policy.Enabled || policy.Revision != campaign.PolicyRevision ||
		!nativeCampaignStringSliceContains(policy.ProfileIDs, campaign.ProfileID) ||
		!nativeCampaignInt64SliceContains(policy.ArtifactIDs, campaign.ArtifactID) {
		return nativeCampaignMonitorSignalOf("cancel", "policy_revoked"), nil
	}
	var configRevision int64
	if err := s.pg.QueryRowContext(ctx, `SELECT revision FROM reverse_native_configs WHERE task_id=$1`, taskID).Scan(&configRevision); err != nil ||
		configRevision != campaign.ConfigRevision {
		return nativeCampaignMonitorSignalOf("cancel", "config_revoked"), nil
	}
	if operatorKind == "intent" {
		if err := s.checkIntent(ctx, taskID, operatorID); err != nil {
			return nativeCampaignMonitorSignalOf("cancel", "operator_revoked"), nil
		}
	}
	// A pause already requested remains a pause only after every cancel-priority
	// revocation above has been evaluated. Cancel always wins over pause.
	if campaign.DesiredState == "paused" {
		return nativeCampaignMonitorSignalOf("pause", "desired_paused"), nil
	}
	return nativeCampaignMonitorSignal{}, nil
}

// Campaign HTTP reads deliberately use the existing DB service only: they never
// initialize the runtime, inspect an image or start a manager/runner.
func nativeCampaignHTTPError(w http.ResponseWriter, err error) {
	code, status := "internal", 500
	details := map[string]any{}
	var ce *db.NativeCampaignError
	if errors.Is(err, sql.ErrNoRows) {
		code, status = "not_found", 404
	} else if errors.As(err, &ce) {
		code, status = nativeCampaignHTTPPublicError(ce.Code), ce.Status
		if ce.State != "" {
			details["state"] = ce.State
		}
		if ce.StateVersion > 0 {
			details["state_version"] = ce.StateVersion
		}
	}
	// Never expose raw DB/OS/runner error messages or arbitrary error details.
	// The operator still needs the real cause, so rejections are logged locally.
	if status >= 400 {
		log.Printf("[native campaign] http action rejected: code=%s status=%d err=%v", code, status, err)
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": strings.ReplaceAll(code, "_", " "), "details": details}})
}
func nativeCampaignHTTPInvalid() error {
	return nativeCampaignAuthErr("invalid_request", 400, "invalid request")
}
func nativeCampaignHTTPInteger(s string, minimum, maximum int64) (int64, error) {
	if s == "" {
		return 0, nativeCampaignHTTPInvalid()
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, nativeCampaignHTTPInvalid()
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < minimum || n > maximum {
		return 0, nativeCampaignHTTPInvalid()
	}
	return n, nil
}
func nativeCampaignHTTPQuery(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, nativeCampaignHTTPInvalid()
	}
	for k, v := range q {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
				break
			}
		}
		if !ok || len(v) != 1 || v[0] == "" {
			return nil, nativeCampaignHTTPInvalid()
		}
	}
	return q, nil
}
func nativeCampaignHTTPQueryInt(q url.Values, key string, fallback, minimum, maximum int64) (int64, error) {
	if !q.Has(key) {
		return fallback, nil
	}
	return nativeCampaignHTTPInteger(q.Get(key), minimum, maximum)
}
func (s *Server) nativeCampaignHTTPRead(w http.ResponseWriter, r *http.Request) (*nativeCampaignService, int64, bool) {
	principal, ok := s.teamPrincipal(r)
	if !ok {
		nativeCampaignHTTPError(w, nativeCampaignAuthErr("authorization_revoked", 401, "authentication required"))
		return nil, 0, false
	}
	if !principal.Admin {
		nativeCampaignHTTPError(w, nativeCampaignAuthErr("authorization_revoked", 403, "administrator required"))
		return nil, 0, false
	}
	if s.campaign == nil || s.campaign.service == nil || !s.campaign.service.enabled {
		nativeCampaignHTTPError(w, nativeCampaignAuthErr("environment_incompatible", 409, "campaign unavailable"))
		return nil, 0, false
	}
	taskID, err := nativeCampaignHTTPInteger(r.PathValue("id"), 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return nil, 0, false
	}
	service := s.campaign.service
	task, err := service.loadTask(r.Context(), taskID)
	if err != nil {
		var ce *db.NativeCampaignError
		if errors.As(err, &ce) && ce.Code == "authorization_revoked" {
			err = sql.ErrNoRows
		}
		nativeCampaignHTTPError(w, err)
		return nil, 0, false
	}
	if task.Deleted || task.Kind != "reverse" {
		nativeCampaignHTTPError(w, sql.ErrNoRows)
		return nil, 0, false
	}
	return service, taskID, true
}

// Public reason codes are deliberately narrower than internal diagnostic text.
func nativeCampaignHTTPPublicReason(value *string) any {
	if value == nil {
		return nil
	}
	switch *value {
	case "completed", "paused", "cancelled", "budget_exhausted", "attempt_budget_exhausted", "max_execs", "max_crashes", "timeout", "execution_timeout", "lease_lost", "process_lost", "cleanup_unknown", "protocol_violation", "engine_error", "target_observation_error", "authorization_revoked", "environment_incompatible", "quota_exceeded", "control_failed", "interrupted", "service_shutdown", "task_paused", "task_cancelled", "policy_revoked", "config_changed", "owner_lost":
		return *value
	default:
		return "unknown"
	}
}
func nativeCampaignHTTPPublicError(value string) string {
	switch value {
	case "invalid_request", "unknown_action", "unknown_field", "not_found", "state_conflict", "idempotency_conflict", "request_in_progress", "terminal_campaign", "resume_required", "resume_blocked", "no_checkpoint", "authorization_revoked", "environment_incompatible", "engine_error", "target_observation_error", "budget_exhausted", "attempt_limit", "cancelled", "cleanup_unknown", "resource_held", "lease_lost", "process_lost", "quota_exceeded", "archive_restore_not_executable", "protocol_violation", "internal":
		return value
	default:
		return "internal"
	}
}
func nativeCampaignHTTPSummary(c *db.NativeCampaign) map[string]any {
	var last any
	if c.LastErrorCode != nil {
		code := nativeCampaignHTTPPublicError(*c.LastErrorCode)
		last = map[string]any{"code": code, "message": strings.ReplaceAll(code, "_", " ")}
	}
	return map[string]any{"id": c.ID, "task_id": c.TaskID, "artifact_id": c.ArtifactID,
		"creator": map[string]any{"kind": c.CreatorKind, "id": c.CreatorID}, "spec_version": c.SpecVersion, "spec_hash": c.SpecHash, "artifact_sha256": c.ArtifactSHA256,
		"profile_id": c.ProfileID, "image_digest": c.ImageDigest, "image_id": c.ImageID, "policy_revision": c.PolicyRevision, "config_revision": c.ConfigRevision,
		"state": c.State, "desired_state": c.DesiredState, "state_version": c.StateVersion, "total_budget_ms": c.TotalBudgetMS, "charged_budget_ms": c.ChargedBudgetMS,
		"remaining_budget_ms": max(int64(0), c.TotalBudgetMS-c.ChargedBudgetMS), "current_attempt_id": c.CurrentAttemptID, "latest_checkpoint_id": c.LatestCheckpointID,
		"cleanup_status": c.CleanupStatus, "pause_origin": c.PauseOrigin, "termination_reason": nativeCampaignHTTPPublicReason(c.TerminationReason), "last_error": last,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt, "started_at": c.StartedAt, "ended_at": c.EndedAt}
}
func (s *Server) nativeCampaignHTTPList(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	q, err := nativeCampaignHTTPQuery(r, "before_id", "limit")
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	before, err := nativeCampaignHTTPQueryInt(q, "before_id", 0, 0, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	limit, err := nativeCampaignHTTPQueryInt(q, "limit", 50, 1, 100)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	rows, err := service.pg.NativeCampaigns(r.Context(), taskID, int(limit), before)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	var next any
	for _, c := range rows {
		out = append(out, map[string]any{"id": c.ID, "artifact_id": c.ArtifactID, "state": c.State, "desired_state": c.DesiredState, "state_version": c.StateVersion, "spec_hash": c.SpecHash, "total_budget_ms": c.TotalBudgetMS, "charged_budget_ms": c.ChargedBudgetMS, "current_attempt_id": c.CurrentAttemptID, "latest_checkpoint_id": c.LatestCheckpointID, "cleanup_status": c.CleanupStatus, "updated_at": c.UpdatedAt})
	}
	if len(rows) == int(limit) {
		next = rows[len(rows)-1].ID
	}
	writeJSON(w, 200, map[string]any{"campaigns": out, "next_before_id": next, "candidate_only": true})
}
func nativeCampaignHTTPAttempt(a *db.NativeCampaignAttempt) map[string]any {
	return map[string]any{"id": a.ID, "attempt_no": a.AttemptNo, "native_run_id": a.NativeRunID, "runtime_run_id": a.RuntimeRunID, "state": a.State, "phase": a.Phase,
		"fencing_token": a.FencingToken, "lease_owner": a.LeaseOwner, "lease_expires_at": a.LeaseExpiresAt, "reserved_budget_ms": a.ReservedBudgetMS, "charged_budget_ms": a.ChargedBudgetMS,
		"started_at": a.StartedAt, "ended_at": a.EndedAt, "termination_reason": nativeCampaignHTTPPublicReason(a.TerminationReason), "cleanup_status": a.CleanupStatus, "resource_hold": a.ResourceHold, "hold_reason": nativeCampaignHTTPPublicReason(a.HoldReason),
		"actual_elapsed_ms": a.ActualElapsedMS, "cleanup_overrun_ms": a.CleanupOverrunMS, "checkpoint_id": a.CheckpointID, "evidence_manifest_id": a.EvidenceManifestID, "budget_overrun": a.BudgetOverrun}
}

// Event payloads are an internal diagnostic format, not a public DTO. Export
// only numeric settlement/identity fields; free text may contain host paths.
func nativeCampaignHTTPEventPayload(raw json.RawMessage) map[string]any {
	out := map[string]any{}
	if len(raw) > 4096 {
		return out
	}
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return out
	}
	for _, k := range []string{"attempt_id", "checkpoint_id", "attempt_budget_ms", "reserved_budget_ms", "charged_budget_ms", "actual_elapsed_ms", "state_version"} {
		if v, ok := values[k]; ok {
			var n int64
			if json.Unmarshal(v, &n) == nil && n >= 0 {
				out[k] = n
			}
		}
	}
	return out
}
func (s *Server) nativeCampaignHTTPStatus(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	q, err := nativeCampaignHTTPQuery(r, "include_events")
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	include := q.Get("include_events") == "true"
	if q.Has("include_events") && !include && q.Get("include_events") != "false" {
		nativeCampaignHTTPError(w, nativeCampaignHTTPInvalid())
		return
	}
	id, err := nativeCampaignHTTPInteger(r.PathValue("campaign_id"), 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	c, err := service.loadCampaign(r.Context(), taskID, id)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	out := map[string]any{"campaign": nativeCampaignHTTPSummary(c), "current_attempt": nil, "latest_checkpoint": nil, "latest_evidence": nil}
	attempts, err := service.pg.NativeCampaignAttempts(r.Context(), taskID, id, 10, 0)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	summaries := make([]map[string]any, 0, len(attempts))
	for _, a := range attempts {
		summaries = append(summaries, map[string]any{"id": a.ID, "attempt_no": a.AttemptNo, "state": a.State})
	}
	out["attempts"] = summaries
	if c.CurrentAttemptID != nil {
		a, e := service.pg.NativeCampaignAttempt(r.Context(), taskID, *c.CurrentAttemptID)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			nativeCampaignHTTPError(w, e)
			return
		}
		if e == nil && a.CampaignID == id {
			out["current_attempt"] = nativeCampaignHTTPAttempt(a)
		}
	}
	if c.LatestCheckpointID != nil {
		cp, e := service.pg.NativeCampaignCheckpoint(r.Context(), taskID, *c.LatestCheckpointID)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			nativeCampaignHTTPError(w, e)
			return
		}
		if e == nil && cp.CampaignID == id {
			m, e := service.pg.NativeCampaignManifest(r.Context(), taskID, cp.ManifestID)
			if e != nil {
				nativeCampaignHTTPError(w, e)
				return
			}
			if m.CampaignID != id {
				nativeCampaignHTTPError(w, sql.ErrNoRows)
				return
			}
			out["latest_checkpoint"] = map[string]any{"id": cp.ID, "manifest_sha256": m.ManifestSHA256, "entry_count": cp.EntryCount, "total_bytes": cp.TotalBytes, "truncated": cp.Truncated, "verified_at": cp.VerifiedAt}
		}
	}
	ev, err := service.pg.NativeCampaignPublishedEvidenceList(r.Context(), taskID, id, 1, 0)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if len(ev) > 0 {
		out["latest_evidence"] = map[string]any{"id": ev[0].ID, "sha256": ev[0].SHA256, "authority": "candidate-only"}
	}
	if include {
		events, e := service.pg.NativeCampaignEvents(r.Context(), taskID, id, 20, 0)
		if e != nil {
			nativeCampaignHTTPError(w, e)
			return
		}
		dto := make([]map[string]any, 0, len(events))
		for _, event := range events {
			dto = append(dto, map[string]any{"id": event.ID, "kind": event.Kind, "payload": nativeCampaignHTTPEventPayload(event.Payload), "created_at": event.CreatedAt})
		}
		out["events"] = dto
	}
	writeJSON(w, 200, out)
}
func (s *Server) nativeCampaignHTTPManifest(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	q, err := nativeCampaignHTTPQuery(r, "checkpoint_id", "max_entries")
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	id, err := nativeCampaignHTTPInteger(r.PathValue("campaign_id"), 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	c, err := service.loadCampaign(r.Context(), taskID, id)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	var cpID int64
	if c.LatestCheckpointID != nil {
		cpID = *c.LatestCheckpointID
	}
	cpID, err = nativeCampaignHTTPQueryInt(q, "checkpoint_id", cpID, 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	limit, err := nativeCampaignHTTPQueryInt(q, "max_entries", 64, 1, 256)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if cpID == 0 {
		nativeCampaignHTTPError(w, nativeCampaignAuthErr("no_checkpoint", 409, "no checkpoint"))
		return
	}
	cp, err := service.pg.NativeCampaignCheckpoint(r.Context(), taskID, cpID)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if cp.CampaignID != id {
		nativeCampaignHTTPError(w, sql.ErrNoRows)
		return
	}
	m, err := service.pg.NativeCampaignManifest(r.Context(), taskID, cp.ManifestID)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if m.CampaignID != id || m.AttemptID != cp.AttemptID {
		nativeCampaignHTTPError(w, sql.ErrNoRows)
		return
	}
	entries, err := service.pg.NativeCampaignEntries(r.Context(), taskID, m.ID)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	dto := make([]map[string]any, 0, min(len(entries), int(limit)))
	for i, e := range entries {
		if i >= int(limit) {
			break
		}
		if !db.NativeSHA256(e.SHA256) || e.StorageKey != nativeCampaignCheckpointStorageKey(taskID, e.SHA256) || !nativeCampaignCheckpointSourceTypeValid(e.SourceType) || validateNativeCampaignSourceRef(e.SourceRef) != nil {
			nativeCampaignHTTPError(w, errors.New("invalid stored object key"))
			return
		}
		dto = append(dto, map[string]any{"sha256": e.SHA256, "length": e.Length, "storage_key": e.StorageKey, "source_type": e.SourceType, "source_ref": e.SourceRef})
	}
	writeJSON(w, 200, map[string]any{"campaign_id": id, "checkpoint_id": cp.ID, "format_version": m.FormatVersion, "manifest_sha256": m.ManifestSHA256, "entry_count": m.EntryCount, "total_bytes": m.TotalBytes, "truncated": m.Truncated, "entries": dto, "preview_truncated": m.EntryCount > len(dto), "manifest_ref": fmt.Sprintf("tasks/%d/reverse/campaigns/%d/checkpoints/%d/manifest.json", taskID, id, cp.ID), "candidate_only": true})
}

func nativeCampaignHTTPString(fields map[string]json.RawMessage, key string, required bool, maximum int) (string, error) {
	raw, ok := fields[key]
	if !ok {
		if required {
			return "", nativeCampaignHTTPInvalid()
		}
		return "", nil
	}
	var value string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &value) != nil || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maximum || (required && value == "") {
		return "", nativeCampaignHTTPInvalid()
	}
	return value, nil
}
func nativeCampaignHTTPBodyInt(fields map[string]json.RawMessage, key string, required bool, fallback, minimum, maximum int64) (int64, error) {
	raw, ok := fields[key]
	if !ok {
		if required {
			return 0, nativeCampaignHTTPInvalid()
		}
		return fallback, nil
	}
	return nativeCampaignHTTPInteger(string(raw), minimum, maximum)
}
func nativeCampaignHTTPActionBody(r *http.Request) (string, map[string]json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, db.NativeCampaignSpecBytes+1))
	if len(raw) > db.NativeCampaignSpecBytes {
		return "", nil, nativeCampaignAuthErr("quota_exceeded", 413, "request exceeds size limit")
	}
	if err != nil || !utf8.Valid(raw) {
		return "", nil, nativeCampaignHTTPInvalid()
	}
	var fields map[string]json.RawMessage
	if strictNativeCampaignUnmarshal(raw, &fields) != nil || fields == nil {
		return "", nil, nativeCampaignHTTPInvalid()
	}
	action, err := nativeCampaignHTTPString(fields, "action", true, 32)
	if err != nil {
		return "", nil, err
	}
	switch action {
	case "create", "validate", "start", "pause", "cancel", "resume":
	default:
		return "", nil, nativeCampaignAuthErr("unknown_action", 400, "unknown POST action")
	}
	// Reuse the shared action-key contract; strict scalar and nested decoding is
	// deliberately performed separately, without converting integers to float64.
	keys := make(map[string]any, len(fields))
	for key, value := range fields {
		keys[key] = value
	}
	keys["action"] = action
	if err := db.ValidateNativeCampaignActionFields(action, keys); err != nil {
		return "", nil, err
	}
	return action, fields, nil
}
func nativeCampaignHTTPRequestID(fields map[string]json.RawMessage) (string, error) {
	id, err := nativeCampaignHTTPString(fields, "request_id", true, 128)
	if err != nil {
		return "", err
	}
	for _, c := range id {
		if c < 0x20 || c > 0x7e {
			return "", nativeCampaignHTTPInvalid()
		}
	}
	if strings.TrimSpace(id) == "" {
		return "", nativeCampaignHTTPInvalid()
	}
	return id, nil
}
func nativeCampaignHTTPInitialSpec(fields map[string]json.RawMessage) (json.RawMessage, int64, error) {
	total, err := nativeCampaignHTTPBodyInt(fields, "total_budget_ms", true, 0, 6000, 86400000)
	if err != nil {
		return nil, 0, err
	}
	budget, err := nativeCampaignHTTPBodyInt(fields, "default_attempt_budget_ms", false, min(int64(60000), total), 6000, min(int64(900000), total))
	if err != nil {
		return nil, 0, err
	}
	maxExec, err := nativeCampaignHTTPBodyInt(fields, "max_executions", false, 1000000, 100, 1000000)
	if err != nil {
		return nil, 0, err
	}
	maxCrash, err := nativeCampaignHTTPBodyInt(fields, "max_crashes", false, 4, 1, 8)
	if err != nil {
		return nil, 0, err
	}
	input := "stdin"
	if _, ok := fields["input_mode"]; ok {
		input, err = nativeCampaignHTTPString(fields, "input_mode", true, 16)
		if err != nil {
			return nil, 0, err
		}
	}
	argv := json.RawMessage(`[]`)
	if raw, ok := fields["argv"]; ok {
		argv = raw
	}
	var rawSeeds []map[string]json.RawMessage
	raw, ok := fields["seeds"]
	if !ok || json.Unmarshal(raw, &rawSeeds) != nil || len(rawSeeds) < 1 || len(rawSeeds) > NativeCampaignMaxSeeds {
		return nil, 0, nativeCampaignHTTPInvalid()
	}
	seeds := make([]nativeCampaignSeed, len(rawSeeds))
	for i, item := range rawSeeds {
		if item == nil {
			return nil, 0, nativeCampaignHTTPInvalid()
		}
		for k := range item {
			if k != "sha256" && k != "data_base64" {
				return nil, 0, nativeCampaignAuthErr("unknown_field", 400, "unknown seed field")
			}
		}
		seeds[i].SHA256, err = nativeCampaignHTTPString(item, "sha256", true, 64)
		if err != nil {
			return nil, 0, err
		}
		seeds[i].DataBase64, err = nativeCampaignHTTPString(item, "data_base64", true, 5464)
		if err != nil {
			return nil, 0, err
		}
	}
	if validateNativeCampaignSeeds(seeds) != nil {
		return nil, 0, nativeCampaignHTTPInvalid()
	}
	spec, err := json.Marshal(map[string]any{"engine": "afl++", "argv": argv, "input_mode": input, "seeds": seeds, "max_executions": maxExec, "max_crashes": maxCrash, "default_attempt_budget_ms": budget})
	if err != nil {
		return nil, 0, nativeCampaignHTTPInvalid()
	}
	if _, err := nativeCampaignStartParameters(spec); err != nil {
		return nil, 0, nativeCampaignHTTPInvalid()
	}
	return spec, total, nil
}

// Draft authorization intentionally does not resolve an image or claim resources.
// The immutable bindings are checked again by the existing pre-transaction auth
// callback; the DB mutation independently checks task/artifact hash and idempotency.
func (s *nativeCampaignService) authorizeDraft(ctx context.Context, c *db.NativeCampaign) error {
	task, err := s.loadTask(ctx, c.TaskID)
	if err != nil {
		return err
	}
	if task.Kind != "reverse" || task.Deleted || task.Archived || task.Paused || db.IsTerminal(task.Status) {
		return nativeCampaignAuthErr("authorization_revoked", 403, "task unavailable")
	}
	if err = s.checkActors(ctx, c, "admin", 0); err != nil {
		return err
	}
	if _, err = s.checkArtifact(ctx, c); err != nil {
		return err
	}
	profile, err := s.findProfile(c.ProfileID)
	if err != nil {
		return err
	}
	if _, err = validateFuzzProfile(profile); err != nil {
		return nativeCampaignAuthErr("environment_incompatible", 409, "profile incompatible")
	}
	digest, _ := profile.Settings["image"].(string)
	if digest != c.ImageDigest || !db.NativeImageDigest(digest) {
		return nativeCampaignAuthErr("environment_incompatible", 409, "profile image changed")
	}
	if _, err = s.checkPolicy(ctx, c); err != nil {
		return err
	}
	return s.checkConfig(ctx, c)
}
func (s *nativeCampaignService) createHTTPDraft(ctx context.Context, taskID int64, fields map[string]json.RawMessage) (*db.NativeCampaignCommandResponse, error) {
	requestID, err := nativeCampaignHTTPRequestID(fields)
	if err != nil {
		return nil, err
	}
	artifactID, err := nativeCampaignHTTPBodyInt(fields, "artifact_id", true, 0, 1, 1<<63-1)
	if err != nil {
		return nil, err
	}
	profileID, err := nativeCampaignHTTPString(fields, "profile_id", true, 64)
	if err != nil {
		return nil, err
	}
	spec, total, err := nativeCampaignHTTPInitialSpec(fields)
	if err != nil {
		return nil, err
	}
	artifact, err := s.pg.GetReverseArtifact(taskID, artifactID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && artifact == nil) {
		return nil, sql.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	profile, err := s.findProfile(profileID)
	if err != nil {
		var ce *db.NativeCampaignError
		if errors.As(err, &ce) && ce.Code == "authorization_revoked" {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	digest, _ := profile.Settings["image"].(string)
	policy, err := s.pg.ReverseRuntimePolicy(taskID)
	if err != nil {
		return nil, err
	}
	var revision int64
	if err = s.pg.QueryRowContext(ctx, `SELECT revision FROM reverse_native_configs WHERE task_id=$1`, taskID).Scan(&revision); err != nil {
		return nil, nativeCampaignAuthErr("environment_incompatible", 409, "configuration unavailable")
	}
	c := &db.NativeCampaign{TaskID: taskID, ArtifactID: artifactID, CreatorKind: "admin", Spec: spec, ArtifactSHA256: artifact.SHA256, ProfileID: profileID, ImageDigest: digest, PolicyRevision: policy.Revision, ConfigRevision: revision, TotalBudgetMS: total}
	if err = s.authorizeDraft(ctx, c); err != nil {
		return nil, err
	}
	return s.pg.CreateNativeCampaignDraft(ctx, func(ctx context.Context, req db.NativeCampaignAuthorizationRequest) error {
		if req.TaskID != taskID || req.Action != "create" || req.ActorKind != "admin" || req.ActorID != 0 {
			return nativeCampaignAuthErr("authorization_revoked", 403, "invalid authority")
		}
		return s.authorizeDraft(ctx, c)
	}, db.NativeCampaignCreateCommand{TaskID: taskID, RequestID: requestID, ArtifactID: artifactID, ProfileID: profileID, CreatorKind: "admin", Spec: spec, ArtifactSHA256: artifact.SHA256, ImageDigest: digest, PolicyRevision: policy.Revision, ConfigRevision: revision, TotalBudgetMS: total, ActorKind: "admin"})
}
func (s *nativeCampaignService) stopHTTPCommand(ctx context.Context, action string, cmd nativeCampaignStateCommand) (*db.NativeCampaignCommandResponse, error) {
	// Stopping never depends on the continued ability to execute a profile/image.
	// The HTTP caller has already authenticated an administrator. Still bind the
	// callback to this action/task/campaign and forward the client's original CAS.
	if _, err := s.loadCampaign(ctx, cmd.TaskID, cmd.CampaignID); err != nil {
		return nil, err
	}

	auth := func(ctx context.Context, req db.NativeCampaignAuthorizationRequest) error {
		if req.TaskID != cmd.TaskID || req.CampaignID != cmd.CampaignID || req.Action != action || req.ActorKind != "admin" || req.ActorID != 0 {
			return nativeCampaignAuthErr("authorization_revoked", 403, "invalid authority")
		}
		_, err := s.loadCampaign(ctx, cmd.TaskID, cmd.CampaignID)
		return err
	}
	state := db.NativeCampaignStateCommand{TaskID: cmd.TaskID, CampaignID: cmd.CampaignID, RequestID: cmd.RequestID, ExpectedStateVersion: cmd.ExpectedStateVersion, Reason: cmd.Reason, ActorKind: "admin"}
	if action == "pause" {
		return s.pg.PauseNativeCampaign(ctx, auth, state)
	}
	if action == "cancel" {
		return s.pg.CancelNativeCampaign(ctx, auth, state)
	}
	return nil, nativeCampaignHTTPInvalid()
}
func nativeCampaignHTTPCommandResponse(w http.ResponseWriter, response *db.NativeCampaignCommandResponse) {
	// Read the stored response snapshot, never reload current state on replay.
	var body map[string]json.RawMessage
	if response == nil || json.Unmarshal(response.Body, &body) != nil {
		nativeCampaignHTTPError(w, errors.New("invalid command response"))
		return
	}
	out := map[string]any{"replayed": response.Replayed}
	if raw, ok := body["campaign"]; ok {
		var c db.NativeCampaign
		if json.Unmarshal(raw, &c) != nil {
			nativeCampaignHTTPError(w, errors.New("invalid draft response"))
			return
		}
		out["campaign"] = nativeCampaignHTTPSummary(&c)
	}
	for _, key := range []string{"campaign_id", "state", "desired_state", "state_version", "cleanup_status", "pause_origin", "charged_budget_ms", "total_budget_ms", "current_attempt_id", "latest_checkpoint_id", "attempt_budget_ms", "already_queued", "already_paused", "already_finalized"} {
		if raw, ok := body[key]; ok {
			out[key] = raw
		}
	}
	writeJSON(w, response.Status, out)
}
func (s *nativeCampaignService) validateHTTP(ctx context.Context, taskID, campaignID int64) (map[string]any, error) {
	c, err := s.loadCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	state, err := s.pg.ValidateNativeCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	checks := map[string]any{}
	allOK := true
	put := func(name string, err error) {
		var code any
		if err != nil {
			allOK = false
			code = "authorization_revoked"
			var ce *db.NativeCampaignError
			if errors.As(err, &ce) {
				code = nativeCampaignHTTPPublicError(ce.Code)
			}
		}
		checks[name] = map[string]any{"ok": err == nil, "code": code}
	}
	var archiveErr error
	if check, ok := state.Checks["archive"]; ok && !check.OK {
		archiveErr = nativeCampaignAuthErr("archive_restore_not_executable", 409, "restored campaign is not executable")
	}
	put("archive", archiveErr)
	task, taskErr := s.loadTask(ctx, taskID)
	if taskErr == nil && (task.Kind != "reverse" || task.Deleted || task.Archived || task.Paused || db.IsTerminal(task.Status)) {
		taskErr = nativeCampaignAuthErr("authorization_revoked", 403, "task unavailable")
	}
	if taskErr == nil {
		taskErr = s.checkActors(ctx, c, "admin", 0)
	}
	put("task", taskErr)
	_, artifactErr := s.checkArtifact(ctx, c)
	put("artifact", artifactErr)
	profile, profileErr := s.findProfile(c.ProfileID)
	var profileMax int
	if profileErr == nil {
		profileMax, profileErr = validateFuzzProfile(profile)
	}
	put("profile", profileErr)
	policy, policyErr := s.checkPolicy(ctx, c)
	put("policy", policyErr)
	configErr := s.checkConfig(ctx, c)
	put("config", configErr)
	var imageErr error
	if allOK {
		_, _, imageErr = s.checkProfileAndImage(ctx, c)
	} else {
		imageErr = nativeCampaignAuthErr("authorization_revoked", 403, "image check requires authorization")
	}
	put("image", imageErr)
	_, budgetErr := s.checkBudget(ctx, c, nil, c.State == "queued", int64(profileMax), int64(policy.MaxDurationMS))
	put("budget", budgetErr)
	checks["budget"].(map[string]any)["remaining_ms"] = max(int64(0), c.TotalBudgetMS-c.ChargedBudgetMS)
	warnings := append([]string{}, state.Warnings...)
	canResume := state.CanResume && allOK
	if canResume {
		if _, err := s.checkCheckpoint(ctx, c); err != nil {
			canResume = false
			warnings = append(warnings, "resume_blocked")
		}
	}
	return map[string]any{"campaign_id": c.ID, "spec_hash": c.SpecHash, "can_start": state.CanStart && allOK, "can_resume": canResume, "checks": checks, "warnings": warnings}, nil
}
func (s *Server) nativeCampaignHTTPAction(w http.ResponseWriter, r *http.Request) {
	service, taskID, ok := s.nativeCampaignHTTPRead(w, r)
	if !ok {
		return
	}
	if _, err := nativeCampaignHTTPQuery(r); err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	action, fields, err := nativeCampaignHTTPActionBody(r)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if action == "create" {
		response, err := service.createHTTPDraft(r.Context(), taskID, fields)
		if err != nil {
			nativeCampaignHTTPError(w, err)
			return
		}
		nativeCampaignHTTPCommandResponse(w, response)
		return
	}
	campaignID, err := nativeCampaignHTTPBodyInt(fields, "campaign_id", true, 0, 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	if action == "validate" {
		result, err := service.validateHTTP(r.Context(), taskID, campaignID)
		if err != nil {
			nativeCampaignHTTPError(w, err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	requestID, err := nativeCampaignHTTPRequestID(fields)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	version, err := nativeCampaignHTTPBodyInt(fields, "expected_state_version", true, 0, 1, 1<<63-1)
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	cmd := nativeCampaignStateCommand{TaskID: taskID, CampaignID: campaignID, RequestID: requestID, ExpectedStateVersion: version, ActorKind: "admin"}
	if _, ok := fields["attempt_budget_ms"]; ok {
		budget, err := nativeCampaignHTTPBodyInt(fields, "attempt_budget_ms", true, 0, 6000, 900000)
		if err != nil {
			nativeCampaignHTTPError(w, err)
			return
		}
		cmd.AttemptBudgetMS = &budget
	}
	if _, ok := fields["reason"]; ok {
		reason, err := nativeCampaignHTTPString(fields, "reason", false, 512)
		if err != nil || strings.ContainsAny(reason, "\x00\\/`;$|\r\n") {
			nativeCampaignHTTPError(w, nativeCampaignHTTPInvalid())
			return
		}
		cmd.Reason = reason
	}
	var response *db.NativeCampaignCommandResponse
	switch action {
	case "start":
		response, err = service.Start(r.Context(), cmd)
	case "resume":
		response, err = service.Resume(r.Context(), cmd)
	case "pause", "cancel":
		response, err = service.stopHTTPCommand(r.Context(), action, cmd)
	}
	if err != nil {
		nativeCampaignHTTPError(w, err)
		return
	}
	nativeCampaignHTTPCommandResponse(w, response)
}
