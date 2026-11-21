package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// T4a tests use only a real disposable PostgreSQL schema, a synthetic in-process
// fake runner and fake artifact/evidence/checkpoint sinks. No Python, Docker,
// AFL, GDB, network target or external service is started.

func t4aHash(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func t4aPolicyJSON(profileID string, artifactID int64) (string, string) {
	return fmt.Sprintf(`["%s"]`, profileID), fmt.Sprintf(`[%d]`, artifactID)
}

type t4aFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newT4AFakeClock() *t4aFakeClock { return &t4aFakeClock{now: time.Now()} }

func (c *t4aFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *t4aFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *t4aFakeClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

type t4aFakeImageResolver struct {
	mu      sync.Mutex
	calls   int
	failAt  int
	imageID string
	err     error
}

func (r *t4aFakeImageResolver) ResolveImageID(context.Context, reverseRuntimeProfile, string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return "", r.err
	}
	if r.failAt > 0 && r.calls >= r.failAt {
		return "", errors.New("synthetic image revocation")
	}
	return r.imageID, nil
}

func (r *t4aFakeImageResolver) Calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type t4aFakeStorage struct {
	mu         sync.Mutex
	verifyErr  error
	persistErr error
	writes     []nativeCampaignEvidenceWrite
}

func (s *t4aFakeStorage) VerifyArtifact(context.Context, int64, *db.ReverseArtifact) error {
	return s.verifyErr
}

func (s *t4aFakeStorage) PersistEvidence(_ context.Context, in nativeCampaignEvidenceWrite) (*nativeCampaignEvidenceRef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.persistErr != nil {
		return nil, s.persistErr
	}
	if len(in.Observation) == 0 || len(in.Observation) > 256<<10 {
		return nil, errors.New("invalid observation size")
	}
	sum := sha256.Sum256(in.Observation)
	sha := hex.EncodeToString(sum[:])
	s.writes = append(s.writes, in)
	return &nativeCampaignEvidenceRef{
		ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/%s.json", in.TaskID, in.CampaignID, sha),
		SHA256:     sha, Observation: in.Observation,
	}, nil
}

func (s *t4aFakeStorage) Writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.writes)
}

func (s *t4aFakeStorage) LastObservation() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.writes) == 0 {
		return nil
	}
	return append([]byte(nil), s.writes[len(s.writes)-1].Observation...)
}

type t4aFakeCheckpointSink struct {
	store *nativeCampaignCheckpointStore // optional real checkpoint fixture dependency
	pg    *db.DB
	mu    sync.Mutex
	calls int
	err   error
}

func (s *t4aFakeCheckpointSink) PersistCheckpoint(ctx context.Context, in nativeCampaignCheckpointWrite) (*db.NativeCampaignCheckpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	if s.store != nil {
		return s.store.PersistCheckpoint(ctx, in)
	}
	label := fmt.Sprintf("t4a-checkpoint-%d-%d", in.AttemptID, s.calls)
	object, err := s.pg.CreateNativeCampaignObject(ctx, db.NativeCampaignObjectInput{
		TaskID: in.TaskID, SHA256: t4aHash(label), Length: 8,
	})
	if err != nil {
		return nil, err
	}
	manifest, err := s.pg.CreateNativeCampaignManifest(ctx, db.NativeCampaignManifestInput{
		TaskID: in.TaskID, CampaignID: in.CampaignID, AttemptID: in.AttemptID,
		ManifestSHA256: t4aHash("manifest-" + label), EntryCount: 1, TotalBytes: 8,
		Entries: []db.NativeCampaignEntryInput{{
			Ordinal: 0, ObjectID: object.ID, SHA256: object.SHA256, Length: 8,
			SourceType: "queue", SourceRef: label,
		}},
	})
	if err != nil {
		return nil, err
	}
	checkpoint, err := s.pg.CreateNativeCampaignCheckpoint(ctx, db.NativeCampaignCheckpointInput{
		TaskID: in.TaskID, CampaignID: in.CampaignID, AttemptID: in.AttemptID,
		ManifestID: manifest.ID, EntryCount: 1, TotalBytes: 8,
	})
	if err != nil {
		return nil, err
	}
	if _, err := s.pg.ExecContext(ctx, `UPDATE native_campaign_checkpoints
		SET state='verified', verified_at=now() WHERE task_id=$1 AND id=$2`,
		in.TaskID, checkpoint.ID); err != nil {
		return nil, err
	}
	return s.pg.NativeCampaignCheckpoint(ctx, in.TaskID, checkpoint.ID)
}

func (s *t4aFakeCheckpointSink) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

type t4aFakeRunner struct {
	mu         sync.Mutex
	start      nativeCampaignRunnerStart
	started    bool
	startErr   error
	controls   []nativeCampaignRunnerControl
	events     chan nativeCampaignRunnerEvent
	finals     chan nativeCampaignRunnerFinal
	waitErr    error
	cleanups   []nativeCampaignCleanupRequest
	cleanup    nativeCampaignCleanupReport
	cleanupErr error
	onControl  func(t4aFakeRunnerControl)
	closed     chan struct{}
	closeOnce  sync.Once

	// startDeadline is the absolute deadline carried by the ctx passed to the
	// only real Start call. startCtxErr records an already-canceled start ctx.
	startDeadline time.Time
	startCtxErr   error

	// afterWait runs inside Wait after a final frame was received but before the
	// final is returned, which lets a test deterministically enqueue a trailing
	// frame for the manager's bounded drain.
	afterWait func()

	// waitBlock deliberately ignores ctx.Done in the non-cooperative close test.
	// waitEntered lets the test know Wait is actually blocked.
	waitBlock       chan struct{}
	waitIgnoreCtx   bool
	waitEntered     chan struct{}
	waitEnteredOnce sync.Once
	closeEventsOnce sync.Once
}

type t4aFakeRunnerControl struct {
	runner  *t4aFakeRunner
	control nativeCampaignRunnerControl
}

func newT4AFakeRunner() *t4aFakeRunner {
	return &t4aFakeRunner{
		events: make(chan nativeCampaignRunnerEvent, 32),
		finals: make(chan nativeCampaignRunnerFinal, 4),
		cleanup: nativeCampaignCleanupReport{
			CleanupVerified: true,
			Containers: []nativeCampaignCleanupContainer{{
				Name: "artex-campaign-fixture", State: "absent", LabelsMatch: true,
			}},
			Staging: struct {
				Present bool `json:"present"`
				Removed bool `json:"removed"`
			}{Present: false, Removed: true},
		},
		closed: make(chan struct{}),
	}
}

func (r *t4aFakeRunner) Start(ctx context.Context, start nativeCampaignRunnerStart) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if deadline, ok := ctx.Deadline(); ok {
		r.startDeadline = deadline
	}
	r.startCtxErr = ctx.Err()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.startErr != nil {
		return r.startErr
	}
	r.start = start
	r.started = true
	return nil
}

func (r *t4aFakeRunner) Control(_ context.Context, control nativeCampaignRunnerControl) error {
	r.mu.Lock()
	r.controls = append(r.controls, control)
	cb := r.onControl
	r.mu.Unlock()
	if cb != nil {
		cb(t4aFakeRunnerControl{runner: r, control: control})
	}
	return nil
}

func (r *t4aFakeRunner) Events() <-chan nativeCampaignRunnerEvent { return r.events }

func (r *t4aFakeRunner) Wait(ctx context.Context) (nativeCampaignRunnerFinal, error) {
	r.mu.Lock()
	block := r.waitBlock
	ignoreCtx := r.waitIgnoreCtx
	entered := r.waitEntered
	r.mu.Unlock()
	if block != nil {
		if entered != nil {
			r.waitEnteredOnce.Do(func() { close(entered) })
		}
		if ignoreCtx {
			<-block
			return nativeCampaignRunnerFinal{}, errors.New("fake runner released without a final")
		}
		select {
		case <-block:
			return nativeCampaignRunnerFinal{}, errors.New("fake runner released without a final")
		case <-ctx.Done():
			return nativeCampaignRunnerFinal{}, ctx.Err()
		}
	}
	select {
	case final := <-r.finals:
		r.mu.Lock()
		afterWait := r.afterWait
		r.mu.Unlock()
		if afterWait != nil {
			afterWait()
		}
		return final, nil
	case <-ctx.Done():
		return nativeCampaignRunnerFinal{}, ctx.Err()
	case <-r.closed:
		return nativeCampaignRunnerFinal{}, errors.New("fake runner closed")
	}
}

func (r *t4aFakeRunner) Cleanup(_ context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cleanups = append(r.cleanups, req)
	if r.cleanupErr != nil {
		return nativeCampaignCleanupReport{}, r.cleanupErr
	}
	report := r.cleanup
	report.ElapsedMS = 1
	return report, nil
}

// Deliver follows the normal completion contract: final frame then Events close.
func (r *t4aFakeRunner) Deliver(final nativeCampaignRunnerFinal) {
	r.DeliverFinalOnly(final)
	r.CloseEvents()
}

// DeliverFinalOnly delivers a final while leaving Events open. It models the
// legal Wait-before-event-close order that the manager must drain boundedly.
func (r *t4aFakeRunner) DeliverFinalOnly(final nativeCampaignRunnerFinal) {
	r.finals <- final
}

func (r *t4aFakeRunner) SendEvent(event nativeCampaignRunnerEvent) {
	r.events <- event
}

func (r *t4aFakeRunner) CloseEvents() {
	r.closeEventsOnce.Do(func() { close(r.events) })
}

func (r *t4aFakeRunner) CloseTransport() {
	r.closeOnce.Do(func() { close(r.closed) })
}

func (r *t4aFakeRunner) StartContext() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.startDeadline, r.startCtxErr
}

func (r *t4aFakeRunner) Snapshot() (nativeCampaignRunnerStart, bool, []nativeCampaignRunnerControl, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.start, r.started, append([]nativeCampaignRunnerControl(nil), r.controls...), len(r.cleanups)
}

func (r *t4aFakeRunner) HasControl(action string) bool {
	_, _, controls, _ := r.Snapshot()
	for _, control := range controls {
		if control.Action == action {
			return true
		}
	}
	return false
}

type t4aFakeRunnerFactory struct {
	mu      sync.Mutex
	runners []*t4aFakeRunner
	hook    func(*t4aFakeRunner)
	err     error
}

func (f *t4aFakeRunnerFactory) New(_ context.Context, _ nativeCampaignRunnerStart) (nativeCampaignRunner, error) {
	runner := newT4AFakeRunner()
	f.mu.Lock()
	if f.hook != nil {
		f.hook(runner)
	}
	f.runners = append(f.runners, runner)
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return runner, err
	}
	return runner, nil
}

func (f *t4aFakeRunnerFactory) Count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.runners)
}

func (f *t4aFakeRunnerFactory) Last() *t4aFakeRunner {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.runners) == 0 {
		return nil
	}
	return f.runners[len(f.runners)-1]
}

func (f *t4aFakeRunnerFactory) Reset() {
	f.mu.Lock()
	f.runners = nil
	f.mu.Unlock()
}

func t4aVerifiedCleanup() nativeCampaignCleanupReport {
	return nativeCampaignCleanupReport{
		CleanupVerified: true,
		Containers:      []nativeCampaignCleanupContainer{{Name: "artex-campaign-fixture", State: "absent", LabelsMatch: true}},
		Staging: struct {
			Present bool `json:"present"`
			Removed bool `json:"removed"`
		}{Present: false, Removed: true},
	}
}

func t4aUnknownCleanup() nativeCampaignCleanupReport {
	return nativeCampaignCleanupReport{CleanupVerified: false}
}

func t4aFinalFor(run *nativeCampaignRun, target string, cleanup nativeCampaignCleanupReport) nativeCampaignRunnerFinal {
	final := nativeCampaignRunnerFinal{
		RequestID: run.expectation().RequestID, TaskID: run.taskID,
		CampaignID: run.campaignID, AttemptID: run.attemptID,
		FencingToken: run.fencingToken, TargetState: target, Phase: "finalize",
		CleanupVerified: cleanup.CleanupVerified,
		Cleanup: nativeCampaignRunnerCleanup{
			OwnedProcessTerminated: cleanup.CleanupVerified,
			ContainerRemoved:       cleanup.CleanupVerified,
			StagingRemoved:         cleanup.CleanupVerified,
		},
		Budget: nativeCampaignRunnerBudget{ReservedMS: 60000, ObservedExecs: 7},
		Reason: target, Candidate: true, Authority: "candidate-only",
	}
	if target == "paused" {
		// This fake runner now supplies a real bounded corpus to real-store
		// resume fixtures, distinct from the campaign's initial "Z" seed.
		record := nativeCampaignCheckpointRecord{Data: []byte("restored"), SHA256: t4aHash("restored"), Length: 8, StorageKey: nativeCampaignCheckpointStorageKey(run.taskID, t4aHash("restored")), SourceType: "queue", SourceRef: "fixture-checkpoint"}
		manifest, _ := nativeCampaignCanonicalManifest(run.taskID, run.campaignID, run.attemptID, []nativeCampaignCheckpointRecord{record})
		digest := sha256.Sum256(manifest)
		final.CheckpointCorpus = []nativeCampaignCheckpointRecord{record}
		final.Checkpoint = &nativeCampaignRunnerCheckpoint{
			FormatVersion: 1, EntryCount: 1, TotalBytes: 8,
			ManifestSHA256: hex.EncodeToString(digest[:]),
		}
	}
	return final
}

type t4aFixture struct {
	t          *testing.T
	pg         *db.DB
	task       *db.Task
	artifact   *db.ReverseArtifact
	profile    reverseRuntimeProfile
	imageID    string
	clock      *t4aFakeClock
	images     *t4aFakeImageResolver
	storage    *t4aFakeStorage
	checkpoint *t4aFakeCheckpointSink
	factory    *t4aFakeRunnerFactory
	service    *nativeCampaignService
	manager    *nativeCampaignManager
	campaign   *db.NativeCampaign
	seq        atomic.Int64
}

func newT4AFixture(t *testing.T, label string) *t4aFixture {
	t.Helper()
	dsn := requireFuzzTestDB(t)
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	task, err := pg.CreateTaskWithOptions("T4a "+label, "owned synthetic campaign", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	// Reverse tasks are created paused by default; an authorized campaign run
	// requires an unpaused task.
	if _, err := pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pg.Exec(`UPDATE native_campaign_attempts
			SET state='failed', cleanup_status='verified', resource_hold=false, hold_reason=NULL
			WHERE task_id=$1 AND resource_hold`, task.ID)
		_ = pg.DeleteTask(task.ID)
		_ = pg.Close()
	})
	artifact, err := pg.AddReverseArtifact(task.ID, db.ReverseArtifact{
		Name: "fixture.elf", Format: "elf",
		Path:      fmt.Sprintf("tasks/%d/reverse/artifacts/fixture.elf", task.ID),
		SizeBytes: 64, SHA256: t4aHash("artifact-" + label),
	})
	if err != nil {
		t.Fatal(err)
	}
	profileID := "lab-linux"
	imageDigest := "sha256:" + t4aHash("image-"+label)
	imageID := "sha256:" + t4aHash("image-id-"+label)
	if _, err := pg.Exec(`INSERT INTO reverse_native_configs(task_id,mode,revision)
		VALUES($1,'analysis',1) ON CONFLICT(task_id) DO UPDATE SET revision=1`, task.ID); err != nil {
		t.Fatal(err)
	}
	profileJSON, artifactJSON := t4aPolicyJSON(profileID, artifact.ID)
	if _, err := pg.Exec(`INSERT INTO reverse_runtime_policies(
		task_id,enabled,profile_ids,artifact_ids,max_duration_ms,revision)
		VALUES($1,true,$2::jsonb,$3::jsonb,600000,1)
		ON CONFLICT(task_id) DO UPDATE SET enabled=true,profile_ids=EXCLUDED.profile_ids,
		artifact_ids=EXCLUDED.artifact_ids,max_duration_ms=600000,revision=1`,
		task.ID, profileJSON, artifactJSON); err != nil {
		t.Fatal(err)
	}
	profile := reverseRuntimeProfile{
		ID: profileID, Name: "Linux fixture", Platform: "linux", Engine: "docker-native",
		Command: "/bin/true",
		Settings: map[string]any{
			"image": imageDigest, "fuzz_enabled": true, "enabled": true,
			"max_duration_ms": 600000, "network": "none", "read_only_root": true,
		},
	}
	clock := newT4AFakeClock()
	images := &t4aFakeImageResolver{imageID: imageID}
	storage := &t4aFakeStorage{}
	checkpoints := &t4aFakeCheckpointSink{pg: pg}
	factory := &t4aFakeRunnerFactory{}
	service, err := newNativeCampaignService(nativeCampaignServiceConfig{
		Enabled: true, DB: pg, Clock: clock,
		Profiles: func() ([]reverseRuntimeProfile, error) { return []reverseRuntimeProfile{profile}, nil },
		Storage:  storage, ImageResolver: images,
		CheckpointValidator: &t4aFakeCheckpointValidator{},
		CheckpointSink:      checkpoints,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager, err := newNativeCampaignManager(nativeCampaignManagerConfig{
		Enabled: true, DB: pg, Service: service, Clock: clock,
		RunnerFactory: factory.New, LeaseTTL: 30000 * time.Millisecond,
		RenewInterval: time.Hour, MonitorInterval: time.Hour, QueueInterval: time.Hour,
		StopTimeout: 3 * time.Second, CleanupTimeout: 3 * time.Second,
		ControlTimeout: 2 * time.Second, StartTimeout: 5 * time.Second,
		DrainTimeout: 300 * time.Millisecond, EOFTimeout: 200 * time.Millisecond,
		InstanceID: "t4a-" + label, DisableBackground: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &t4aFixture{
		t: t, pg: pg, task: task, artifact: artifact, profile: profile,
		imageID: imageID, clock: clock, images: images, storage: storage,
		checkpoint: checkpoints, factory: factory, service: service, manager: manager,
	}
}

type t4aFakeCheckpointValidator struct{ err error }

func (v *t4aFakeCheckpointValidator) ValidateCheckpoint(context.Context, int64, int64, int64) error {
	return v.err
}

// Only the resume integration fixtures opt into real immutable storage/loading;
// other T4a fault-injection fixtures keep their existing explicit fake boundary.
func (f *t4aFixture) useRealCheckpointStore() *nativeCampaignCheckpointStore {
	f.t.Helper()
	store, err := newNativeCampaignCheckpointStore(f.pg, f.t.TempDir())
	if err != nil {
		f.t.Fatal(err)
	}
	f.checkpoint.store = store
	f.service.checkpoints = store
	return store
}

func (f *t4aFixture) createCampaign(label string) *db.NativeCampaign {
	f.t.Helper()
	spec, _ := json.Marshal(map[string]any{
		"engine": "afl++", "default_attempt_budget_ms": 60000,
		"artifact_sha256": f.artifact.SHA256,
		"argv":            []string{}, "input_mode": "stdin",
		"seeds":          []nativeCampaignSeed{{SHA256: "bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83", DataBase64: "Wg=="}},
		"max_executions": 1000000, "max_crashes": 4,
	})
	requestID := fmt.Sprintf("t4a-create-%s-%d", label, f.seq.Add(1))
	resp, err := f.pg.CreateNativeCampaignDraft(context.Background(), func(context.Context, db.NativeCampaignAuthorizationRequest) error { return nil },
		db.NativeCampaignCreateCommand{
			TaskID: f.task.ID, RequestID: requestID, ArtifactID: f.artifact.ID,
			ProfileID: f.profile.ID, CreatorKind: "admin",
			Spec: spec, ArtifactSHA256: f.artifact.SHA256,
			ImageDigest:    f.profile.Settings["image"].(string),
			PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: 600000,
		})
	if err != nil {
		f.t.Fatal(err)
	}
	var body struct {
		Campaign db.NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&body); err != nil {
		f.t.Fatal(err)
	}
	return &body.Campaign
}

func (f *t4aFixture) createCampaignInput(label, creatorKind string, creatorID int64, totalBudget int64) *db.NativeCampaign {
	f.t.Helper()
	spec, _ := json.Marshal(map[string]any{
		"engine": "afl++", "default_attempt_budget_ms": 60000,
		"artifact_sha256": f.artifact.SHA256,
		"argv":            []string{}, "input_mode": "stdin",
		"seeds":          []nativeCampaignSeed{{SHA256: "bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83", DataBase64: "Wg=="}},
		"max_executions": 1000000, "max_crashes": 4,
	})
	requestID := fmt.Sprintf("t4a-create-%s-%d", label, f.seq.Add(1))
	resp, err := f.pg.CreateNativeCampaignDraft(context.Background(), func(context.Context, db.NativeCampaignAuthorizationRequest) error { return nil },
		db.NativeCampaignCreateCommand{
			TaskID: f.task.ID, RequestID: requestID, ArtifactID: f.artifact.ID,
			ProfileID: f.profile.ID, CreatorKind: creatorKind, CreatorID: creatorID,
			Spec: spec, ArtifactSHA256: f.artifact.SHA256,
			ImageDigest:    f.profile.Settings["image"].(string),
			PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: totalBudget,
		})
	if err != nil {
		f.t.Fatal(err)
	}
	var body struct {
		Campaign db.NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&body); err != nil {
		f.t.Fatal(err)
	}
	return &body.Campaign
}

func (f *t4aFixture) createCampaignWithSpec(label string, totalBudget, defaultBudget int64) *db.NativeCampaign {
	f.t.Helper()
	spec, _ := json.Marshal(map[string]any{
		"engine": "afl++", "default_attempt_budget_ms": defaultBudget,
		"artifact_sha256": f.artifact.SHA256,
		"argv":            []string{}, "input_mode": "stdin",
		"seeds":          []nativeCampaignSeed{{SHA256: "bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83", DataBase64: "Wg=="}},
		"max_executions": 1000000, "max_crashes": 4,
	})
	requestID := fmt.Sprintf("t4a-create-%s-%d", label, f.seq.Add(1))
	resp, err := f.pg.CreateNativeCampaignDraft(context.Background(), func(context.Context, db.NativeCampaignAuthorizationRequest) error { return nil },
		db.NativeCampaignCreateCommand{
			TaskID: f.task.ID, RequestID: requestID, ArtifactID: f.artifact.ID,
			ProfileID: f.profile.ID, CreatorKind: "admin",
			Spec: spec, ArtifactSHA256: f.artifact.SHA256,
			ImageDigest:    f.profile.Settings["image"].(string),
			PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: totalBudget,
		})
	if err != nil {
		f.t.Fatal(err)
	}
	var body struct {
		Campaign db.NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&body); err != nil {
		f.t.Fatal(err)
	}
	return &body.Campaign
}

func (f *t4aFixture) startWithBudget(campaign *db.NativeCampaign, budget int64) *db.NativeCampaign {
	f.t.Helper()
	requestID := fmt.Sprintf("t4a-start-budget-%d-%d", campaign.ID, f.seq.Add(1))
	resp, err := f.service.Start(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: campaign.StateVersion, AttemptBudgetMS: &budget,
		ActorKind: "admin",
	})
	if err != nil {
		f.t.Fatalf("service start with budget: %v", err)
	}
	if resp.Status != 202 {
		f.t.Fatalf("service start with budget status=%d", resp.Status)
	}
	return f.reloadCampaign(campaign)
}

func (f *t4aFixture) startOneRun(t *testing.T, label string) (*db.NativeCampaign, *nativeCampaignRun) {
	t.Helper()
	campaign := f.queuedCampaign(label)
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatalf("manager step: %v", err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	if campaign.CurrentAttemptID == nil {
		t.Fatal("campaign has no current attempt")
	}
	run := f.activeRun(*campaign.CurrentAttemptID)
	if run == nil {
		t.Fatal("active run is nil")
	}
	return campaign, run
}

func (f *t4aFixture) start(campaign *db.NativeCampaign, actorKind string, actorID int64) *db.NativeCampaign {
	f.t.Helper()
	if actorKind == "" {
		actorKind = "admin"
	}
	requestID := fmt.Sprintf("t4a-start-%d-%d", campaign.ID, f.seq.Add(1))
	resp, err := f.service.Start(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: campaign.StateVersion, ActorKind: actorKind, ActorID: actorID,
	})
	if err != nil {
		f.t.Fatalf("service start: %v", err)
	}
	if resp.Status != 202 {
		f.t.Fatalf("service start status=%d", resp.Status)
	}
	return f.reloadCampaign(campaign)
}

func (f *t4aFixture) reloadCampaign(campaign *db.NativeCampaign) *db.NativeCampaign {
	f.t.Helper()
	got, err := f.pg.NativeCampaign(context.Background(), campaign.TaskID, campaign.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *t4aFixture) reloadAttempt(attempt *db.NativeCampaignAttempt) *db.NativeCampaignAttempt {
	f.t.Helper()
	got, err := f.pg.NativeCampaignAttempt(context.Background(), attempt.TaskID, attempt.ID)
	if err != nil {
		f.t.Fatal(err)
	}
	return got
}

func (f *t4aFixture) startManager() {
	f.t.Helper()
	if err := f.manager.Start(context.Background()); err != nil {
		f.t.Fatalf("manager start: %v", err)
	}
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.manager.Close(ctx)
	})
}

func (f *t4aFixture) queuedCampaign(label string) *db.NativeCampaign {
	f.t.Helper()
	campaign := f.createCampaign(label)
	return f.start(campaign, "admin", 0)
}

func (f *t4aFixture) activeRun(attemptID int64) *nativeCampaignRun {
	f.t.Helper()
	f.manager.mu.Lock()
	defer f.manager.mu.Unlock()
	return f.manager.active[attemptID]
}

func (f *t4aFixture) attemptCount() int {
	f.t.Helper()
	var count int
	if err := f.pg.QueryRow(`SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1`, f.task.ID).Scan(&count); err != nil {
		f.t.Fatal(err)
	}
	return count
}

func (f *t4aFixture) intent(state, role string) int64 {
	f.t.Helper()
	payload, _ := json.Marshal(map[string]any{"contract": map[string]any{"execution_role": role}})
	var id int64
	if err := f.pg.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,state,payload)
		VALUES($1,'intent',$2,$3) RETURNING id`, f.task.ExplorationID, state, payload).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *t4aFixture) waitFor(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (f *t4aFixture) driveFinal(t *testing.T, attemptID int64, target string, cleanup nativeCampaignCleanupReport) {
	t.Helper()
	var run *nativeCampaignRun
	f.waitFor(t, "active run", func() bool {
		run = f.activeRun(attemptID)
		return run != nil
	})
	runner := f.factory.Last()
	if runner == nil {
		t.Fatal("no fake runner")
	}
	runner.mu.Lock()
	runner.cleanup = cleanup
	runner.mu.Unlock()
	runner.Deliver(t4aFinalFor(run, target, cleanup))
	f.waitFor(t, "finalization", func() bool { return f.manager.ActiveCount() == 0 })
}

func (f *t4aFixture) expectErrorCode(err error, want string) {
	f.t.Helper()
	if err == nil {
		f.t.Fatalf("expected error code %q, got nil", want)
	}
	if code := db.NativeCampaignErrorCode(err); code != want {
		f.t.Fatalf("error code=%q want=%q err=%v", code, want, err)
	}
}

func (f *t4aFixture) startExpectError(campaign *db.NativeCampaign, actorKind string, actorID int64, want string) {
	f.t.Helper()
	if actorKind == "" {
		actorKind = "admin"
	}
	_, err := f.service.Start(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: campaign.ID,
		RequestID:            fmt.Sprintf("t4a-start-err-%d-%d", campaign.ID, f.seq.Add(1)),
		ExpectedStateVersion: campaign.StateVersion,
		ActorKind:            actorKind, ActorID: actorID,
	})
	f.expectErrorCode(err, want)
}

func TestNativeCampaignGateAndQueueOnly(t *testing.T) {
	t.Setenv("ARTEX_NATIVE_CAMPAIGN", "")
	if nativeCampaignFeatureEnabled() {
		t.Fatal("default-off gate is enabled")
	}
	t.Setenv("ARTEX_NATIVE_CAMPAIGN", "1")
	if !nativeCampaignFeatureEnabled() {
		t.Fatal("explicit gate is not enabled")
	}
	f := newT4AFixture(t, "gate-queue")
	campaign := f.createCampaign("gate-queue")
	disabled := *f.service
	disabled.enabled = false
	if _, err := disabled.Start(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: campaign.ID, RequestID: "t4a-disabled-start",
		ExpectedStateVersion: campaign.StateVersion, ActorKind: "admin",
	}); !errors.Is(err, ErrNativeCampaignDisabled) {
		t.Fatalf("disabled start err=%v", err)
	}
	stillDraft := f.reloadCampaign(campaign)
	if stillDraft.State != "draft" {
		t.Fatalf("disabled start mutated campaign: %+v", stillDraft)
	}

	campaign = f.start(campaign, "admin", 0)
	if campaign.State != "queued" || campaign.DesiredState != "running" {
		t.Fatalf("start did not only queue: %+v", campaign)
	}
	if f.factory.Count() != 0 || f.attemptCount() != 0 {
		t.Fatalf("service.Start launched work: factory=%d attempts=%d", f.factory.Count(), f.attemptCount())
	}
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "manager claim", func() bool { return f.attemptCount() == 1 && f.factory.Count() == 1 })
	campaign = f.reloadCampaign(campaign)
	if campaign.State != "running" || campaign.CurrentAttemptID == nil {
		t.Fatalf("manager did not claim: %+v", campaign)
	}
	runner := f.factory.Last()
	start, started, _, _ := runner.Snapshot()
	if !started || start.ExecutionDeadline == "" || start.EnvelopeDeadline == "" {
		t.Fatalf("runner start=%+v started=%v", start, started)
	}
	if start.AttemptBudgetMS != 60000 || start.ExecutionWindowMS != 55000 {
		t.Fatalf("unexpected budget frame: %+v", start)
	}
}

func TestNativeCampaignAuthorizationBindings(t *testing.T) {
	t.Run("task_archived", func(t *testing.T) {
		f := newT4AFixture(t, "auth-archived")
		campaign := f.createCampaign("archived")
		if _, err := f.pg.Exec(`UPDATE tasks SET archived_at=now() WHERE id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("task_paused", func(t *testing.T) {
		f := newT4AFixture(t, "auth-paused")
		campaign := f.createCampaign("paused")
		if _, err := f.pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("profile_disabled", func(t *testing.T) {
		f := newT4AFixture(t, "auth-profile-disabled")
		campaign := f.createCampaign("profile-disabled")
		profile := f.profile
		profile.Settings["enabled"] = false
		f.service.profiles = func() ([]reverseRuntimeProfile, error) { return []reverseRuntimeProfile{profile}, nil }
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("fuzz_disabled", func(t *testing.T) {
		f := newT4AFixture(t, "auth-fuzz-disabled")
		campaign := f.createCampaign("fuzz-disabled")
		profile := f.profile
		profile.Settings["fuzz_enabled"] = false
		f.service.profiles = func() ([]reverseRuntimeProfile, error) { return []reverseRuntimeProfile{profile}, nil }
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("immutable_image", func(t *testing.T) {
		f := newT4AFixture(t, "auth-image")
		campaign := f.createCampaign("image")
		profile := f.profile
		profile.Settings["image"] = "latest"
		f.service.profiles = func() ([]reverseRuntimeProfile, error) { return []reverseRuntimeProfile{profile}, nil }
		_, err := f.service.Start(context.Background(), nativeCampaignStateCommand{
			TaskID: f.task.ID, CampaignID: campaign.ID, RequestID: "t4a-image-start",
			ExpectedStateVersion: campaign.StateVersion, ActorKind: "admin",
		})
		if err == nil {
			t.Fatal("mutable image accepted")
		}
	})
	t.Run("image_resolver_missing", func(t *testing.T) {
		f := newT4AFixture(t, "auth-resolver")
		campaign := f.createCampaign("resolver")
		f.service.images = nil
		f.startExpectError(campaign, "admin", 0, "environment_incompatible")
	})
	t.Run("storage_missing", func(t *testing.T) {
		f := newT4AFixture(t, "auth-storage")
		campaign := f.createCampaign("storage")
		f.service.storage = nil
		f.startExpectError(campaign, "admin", 0, "environment_incompatible")
	})
	t.Run("policy_revision", func(t *testing.T) {
		f := newT4AFixture(t, "auth-policy")
		campaign := f.createCampaign("policy")
		if _, err := f.pg.Exec(`UPDATE reverse_runtime_policies SET revision=2 WHERE task_id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("policy_disabled", func(t *testing.T) {
		f := newT4AFixture(t, "auth-policy-disabled")
		campaign := f.createCampaign("policy-disabled")
		if _, err := f.pg.Exec(`UPDATE reverse_runtime_policies SET enabled=false WHERE task_id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "authorization_revoked")
	})
	t.Run("config_revision", func(t *testing.T) {
		f := newT4AFixture(t, "auth-config")
		campaign := f.createCampaign("config")
		if _, err := f.pg.Exec(`UPDATE reverse_native_configs SET revision=2 WHERE task_id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "environment_incompatible")
	})
	t.Run("budget_exhausted", func(t *testing.T) {
		f := newT4AFixture(t, "auth-budget")
		campaign := f.createCampaignInput("budget", "admin", 0, 6000)
		if _, err := f.pg.Exec(`UPDATE native_campaigns SET charged_budget_ms=6000 WHERE task_id=$1 AND id=$2`, f.task.ID, campaign.ID); err != nil {
			t.Fatal(err)
		}
		f.startExpectError(campaign, "admin", 0, "budget_exhausted")
	})
	t.Run("intent_not_dynamic", func(t *testing.T) {
		f := newT4AFixture(t, "auth-intent")
		intentID := f.intent("running", "reverse_static")
		campaign := f.createCampaignInput("intent", "intent", intentID, 600000)
		f.startExpectError(campaign, "intent", intentID, "authorization_revoked")
		if _, err := f.pg.Exec(`UPDATE exploration_nodes SET payload='{"contract":{"execution_role":"reverse_dynamic"}}' WHERE id=$1`, intentID); err != nil {
			t.Fatal(err)
		}
		started := f.start(campaign, "intent", intentID)
		if started.State != "queued" {
			t.Fatalf("dynamic intent start=%+v", started)
		}
	})
}

type t4aFailingStartLeaseStore struct {
	nativeCampaignLeaseStore
	err error
}

func (s t4aFailingStartLeaseStore) MarkNativeCampaignAttemptStarted(context.Context, db.NativeCampaignAttemptStartCommand) (*db.NativeCampaignLeaseResult, error) {
	return nil, s.err
}

type t4aFailingRenewLeaseStore struct {
	nativeCampaignLeaseStore
	mu    sync.Mutex
	fail  int
	calls int
	armed atomic.Bool
}

// Arm makes renewal failures active only after Start has been confirmed, so the
// start-permission checks cannot consume the three-failure budget.
func (s *t4aFailingRenewLeaseStore) Arm() { s.armed.Store(true) }

func (s *t4aFailingRenewLeaseStore) RenewNativeCampaignAttemptLease(ctx context.Context, cmd db.NativeCampaignLeaseCommand) (*db.NativeCampaignLeaseResult, error) {
	s.mu.Lock()
	s.calls++
	fail := s.armed.Load() && s.fail > 0
	if fail {
		s.fail--
	}
	s.mu.Unlock()
	if fail {
		return nil, errors.New("synthetic lease database failure")
	}
	return s.nativeCampaignLeaseStore.RenewNativeCampaignAttemptLease(ctx, cmd)
}

func TestNativeCampaignManagerClaimFailureZeroStart(t *testing.T) {
	t.Run("mark_started_cas_failed", func(t *testing.T) {
		f := newT4AFixture(t, "claim-cas")
		queued := f.queuedCampaign("claim-cas")
		base := nativeCampaignDBLeaseStore{pg: f.pg}
		failing := t4aFailingStartLeaseStore{nativeCampaignLeaseStore: base, err: errors.New("synthetic mark-started failure")}
		manager, err := newNativeCampaignManager(nativeCampaignManagerConfig{
			Enabled: true, DB: f.pg, Service: f.service, Clock: f.clock,
			RunnerFactory: f.factory.New, LeaseStore: failing,
			StopTimeout: 3 * time.Second, CleanupTimeout: 3 * time.Second, ControlTimeout: 2 * time.Second,
			DisableBackground: true, InstanceID: "t4a-claim-cas",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = manager.Close(ctx)
		})
		if err := manager.Step(context.Background()); err == nil {
			t.Fatal("Step unexpectedly succeeded with failed start CAS")
		}
		if f.factory.Count() != 0 {
			t.Fatalf("factory started after failed start CAS: %d", f.factory.Count())
		}
		if manager.ActiveCount() != 0 {
			t.Fatalf("active run leaked: %d", manager.ActiveCount())
		}
		attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, queued.ID, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(attempts) != 1 || attempts[0].State != "interrupted" || !attempts[0].ResourceHold {
			t.Fatalf("attempts after failed start=%+v", attempts)
		}
	})
	t.Run("resource_held", func(t *testing.T) {
		f := newT4AFixture(t, "claim-held")
		held := f.queuedCampaign("claim-held-a")
		f.startManager()
		outcome, err := f.service.Claim(context.Background(), f.task.ID, held.ID, "held-claim")
		if err != nil {
			t.Fatal(err)
		}
		if outcome == nil || outcome.Claim == nil {
			t.Fatal("manual claim failed")
		}
		f.queuedCampaign("claim-held-b")
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.factory.Count() != 0 {
			t.Fatalf("factory started while global hold exists: %d", f.factory.Count())
		}
	})
}

func TestNativeCampaignManagerDualContention(t *testing.T) {
	f := newT4AFixture(t, "dual")
	secondFactory := &t4aFakeRunnerFactory{}
	secondService, err := newNativeCampaignService(nativeCampaignServiceConfig{
		Enabled: true, DB: f.pg, Clock: f.clock,
		Profiles: func() ([]reverseRuntimeProfile, error) { return []reverseRuntimeProfile{f.profile}, nil },
		Storage:  f.storage, ImageResolver: f.images,
		CheckpointValidator: &t4aFakeCheckpointValidator{}, CheckpointSink: f.checkpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondManager, err := newNativeCampaignManager(nativeCampaignManagerConfig{
		Enabled: true, DB: f.pg, Service: secondService, Clock: f.clock,
		RunnerFactory: secondFactory.New, LeaseTTL: 30 * time.Second,
		StopTimeout: 3 * time.Second, CleanupTimeout: 3 * time.Second, ControlTimeout: 2 * time.Second,
		DisableBackground: true, InstanceID: "t4a-dual-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	f.queuedCampaign("dual")
	f.startManager()
	if err := secondManager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = secondManager.Close(ctx)
	})
	var wg sync.WaitGroup
	wg.Add(2)
	start := make(chan struct{})
	go func() {
		defer wg.Done()
		<-start
		_ = f.manager.Step(context.Background())
	}()
	go func() {
		defer wg.Done()
		<-start
		_ = secondManager.Step(context.Background())
	}()
	close(start)
	wg.Wait()
	total := f.factory.Count() + secondFactory.Count()
	if total != 1 {
		t.Fatalf("dual managers started %d runners, want exactly 1", total)
	}
	if f.attemptCount() != 1 {
		t.Fatalf("dual managers created %d attempts, want 1", f.attemptCount())
	}
	if f.manager.ActiveCount()+secondManager.ActiveCount() != 1 {
		t.Fatalf("active managers=%d/%d", f.manager.ActiveCount(), secondManager.ActiveCount())
	}
}

func TestNativeCampaignClaimRevocationBeforeStart(t *testing.T) {
	f := newT4AFixture(t, "revoke-gap")
	campaign := f.queuedCampaign("revoke-gap")
	f.images.mu.Lock()
	f.images.calls = 0
	f.images.failAt = 3 // claim precheck + T3 claim authorizer + post-claim recheck
	f.images.mu.Unlock()
	f.startManager()
	_ = f.manager.Step(context.Background())
	if f.factory.Count() != 0 {
		t.Fatalf("factory started after post-claim revocation: %d", f.factory.Count())
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts=%d", len(attempts))
	}
	attempt := attempts[0]
	if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("revoked attempt=%+v", attempt)
	}
	if f.manager.ActiveCount() != 0 {
		t.Fatalf("revoked run still active: %d", f.manager.ActiveCount())
	}
}

func TestNativeCampaignLeaseThreeFailuresBoundedStop(t *testing.T) {
	f := newT4AFixture(t, "lease-three")
	campaign := f.queuedCampaign("lease-three")
	base := nativeCampaignDBLeaseStore{pg: f.pg}
	failing := &t4aFailingRenewLeaseStore{nativeCampaignLeaseStore: base, fail: 3}
	manager, err := newNativeCampaignManager(nativeCampaignManagerConfig{
		Enabled: true, DB: f.pg, Service: f.service, Clock: f.clock,
		RunnerFactory: f.factory.New, LeaseStore: failing,
		StopTimeout: 3 * time.Second, CleanupTimeout: 3 * time.Second, ControlTimeout: 2 * time.Second,
		DisableBackground: true, InstanceID: "t4a-lease-three-store",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	if err := manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.factory.Count() != 1 {
		t.Fatalf("factory=%d", f.factory.Count())
	}
	f.waitFor(t, "active run", func() bool { return manager.ActiveCount() == 1 })
	// Only injections after the runner Start is confirmed count toward the
	// three-failure stop. Start-permission checks use a separate read-only
	// gate and must not consume this budget.
	failing.Arm()
	for i := 0; i < 3; i++ {
		_ = manager.StepLeases(context.Background())
	}
	f.waitFor(t, "lease failure stop", func() bool { return manager.ActiveCount() == 0 })
	runner := f.factory.Last()
	if !runner.HasControl("cancel") {
		_, _, controls, _ := runner.Snapshot()
		t.Fatalf("runner did not receive cancel: %+v", controls)
	}
	runner.mu.Lock()
	cleanups := len(runner.cleanups)
	runner.mu.Unlock()
	if cleanups == 0 {
		t.Fatal("runner cleanup was not requested")
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].State != "interrupted" || attempts[0].CleanupStatus != "unknown" || !attempts[0].ResourceHold {
		t.Fatalf("attempt after lease failures=%+v", attempts)
	}
}

func TestNativeCampaignLeaseExpiryLateToken(t *testing.T) {
	f := newT4AFixture(t, "lease-expiry")
	campaign := f.queuedCampaign("lease-expiry")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	if _, err := f.pg.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND campaign_id=$2`, f.task.ID, campaign.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.StepLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "expired lease stop", func() bool { return f.manager.ActiveCount() == 0 })
	runner := f.factory.Last()
	if !runner.HasControl("cancel") {
		t.Fatal("expired lease did not cancel the runner")
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].State != "interrupted" || !attempts[0].ResourceHold {
		t.Fatalf("expired lease attempt=%+v", attempts)
	}
	// A late direct final write with the old token must not change the ledger.
	evidence, err := f.pg.CreateNativeCampaignEvidence(context.Background(), db.NativeCampaignEvidenceInput{
		TaskID: f.task.ID, CampaignID: campaign.ID, AttemptID: attempts[0].ID,
		Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/late.json", f.task.ID, campaign.ID),
		SHA256: t4aHash("late-evidence"), Observation: json.RawMessage(`{"candidate_only":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.pg.FinalizeNativeCampaignAttempt(context.Background(), func(context.Context, db.NativeCampaignAuthorizationRequest) error { return nil },
		db.NativeCampaignFinalizeCommand{
			TaskID: f.task.ID, CampaignID: campaign.ID, AttemptID: attempts[0].ID,
			FencingToken: attempts[0].FencingToken, LeaseOwner: attempts[0].LeaseOwner,
			LeaseInstance: attempts[0].LeaseInstance, TargetState: "failed",
			Phase: "finalize", CleanupStatus: "unknown", EvidenceID: evidence.ID,
			ActualElapsedMS: 1000, CleanupReserveMS: 5000,
		})
	if err == nil {
		t.Fatal("late final after lease expiry was accepted")
	}
}

func TestNativeCampaignCancelEscalation(t *testing.T) {
	f := newT4AFixture(t, "escalate")
	campaign := f.queuedCampaign("escalate")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	if campaign.CurrentAttemptID == nil {
		t.Fatal("campaign has no current attempt")
	}
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	runner.onControl = func(c t4aFakeRunnerControl) {
		if c.control.Action == "cancel" {
			c.runner.Deliver(t4aFinalFor(run, "cancelled", t4aVerifiedCleanup()))
		}
	}
	if _, err := f.pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !runner.HasControl("pause") {
		t.Fatal("task pause did not reach the runner")
	}
	stopping := f.reloadCampaign(campaign)
	if stopping.State != "stopping" || stopping.DesiredState != "paused" {
		var pauseStatus int
		var pauseBody string
		_ = f.pg.QueryRow(`SELECT response_status,response_body::text FROM native_campaign_requests
			WHERE task_id=$1 AND campaign_id=$2 AND action='pause' ORDER BY id DESC LIMIT 1`,
			f.task.ID, campaign.ID).Scan(&pauseStatus, &pauseBody)
		t.Fatalf("pause transition=%+v pause_status=%d body=%s", stopping, pauseStatus, pauseBody)
	}
	if _, err := f.pg.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "cancel escalation final", func() bool { return f.manager.ActiveCount() == 0 })
	_, _, controls, _ := runner.Snapshot()
	var pauseAt, cancelAt = -1, -1
	for i, c := range controls {
		if c.Action == "pause" && pauseAt < 0 {
			pauseAt = i
		}
		if c.Action == "cancel" {
			cancelAt = i
		}
	}
	if pauseAt < 0 || cancelAt <= pauseAt {
		t.Fatalf("controls=%v want pause before cancel", controls)
	}
	final := f.reloadCampaign(campaign)
	if final.State != "cancelled" || final.CleanupStatus != "verified" {
		t.Fatalf("escalated campaign=%+v", final)
	}
}

func TestNativeCampaignCleanupUnknownBlocksAndRetryOnlyCleans(t *testing.T) {
	f := newT4AFixture(t, "cleanup-block")
	campaign := f.queuedCampaign("cleanup-block")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	attemptID := *campaign.CurrentAttemptID
	f.driveFinal(t, attemptID, "failed", t4aUnknownCleanup())
	failed := f.reloadCampaign(campaign)
	if failed.State != "failed" || failed.CleanupStatus != "unknown" {
		t.Fatalf("cleanup unknown campaign=%+v", failed)
	}
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.ResourceHold {
		t.Fatal("cleanup unknown released the global hold")
	}
	next := f.queuedCampaign("cleanup-block-next")
	beforeFactory := f.factory.Count()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.factory.Count() != beforeFactory {
		t.Fatal("a new campaign started while the previous hold remained")
	}
	// Retry cleanup only: verified cleanup releases the hold without executing
	// the old target or creating a new attempt.
	if _, err := f.service.RetryCleanup(context.Background(), db.NativeCampaignCleanupCommand{
		TaskID: f.task.ID, CampaignID: campaign.ID, AttemptID: attemptID,
		CleanupVerified: true, CleanupElapsedMS: 500, ActorKind: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	oldAttempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldAttempts) != 1 {
		t.Fatalf("cleanup retry created new attempts: %d", len(oldAttempts))
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "next campaign claim", func() bool { return f.factory.Count() == beforeFactory+1 })
	newAttempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, next.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(newAttempts) != 1 {
		t.Fatalf("next campaign attempts=%d", len(newAttempts))
	}
}

func TestNativeCampaignEvidenceAndCheckpointSinkFailClosed(t *testing.T) {
	t.Run("evidence_sink_failure", func(t *testing.T) {
		f := newT4AFixture(t, "evidence-fail")
		campaign := f.queuedCampaign("evidence-fail")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		f.storage.mu.Lock()
		f.storage.persistErr = errors.New("synthetic evidence sink failure")
		f.storage.mu.Unlock()
		f.driveFinal(t, *campaign.CurrentAttemptID, "completed", t4aVerifiedCleanup())
		got := f.reloadCampaign(campaign)
		if got.State == "completed" || got.State == "paused" {
			t.Fatalf("sink failure still produced %q", got.State)
		}
		attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, *campaign.CurrentAttemptID)
		if err != nil {
			t.Fatal(err)
		}
		if !attempt.ResourceHold || attempt.CleanupStatus != "unknown" {
			t.Fatalf("sink failure attempt=%+v", attempt)
		}
	})
	t.Run("checkpoint_sink_missing", func(t *testing.T) {
		f := newT4AFixture(t, "checkpoint-missing")
		campaign := f.queuedCampaign("checkpoint-missing")
		f.service.checkpointSink = nil
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		f.driveFinal(t, *campaign.CurrentAttemptID, "paused", t4aVerifiedCleanup())
		got := f.reloadCampaign(campaign)
		if got.State == "paused" {
			t.Fatal("paused final accepted without a checkpoint sink")
		}
		if got.State != "failed" {
			t.Fatalf("checkpoint sink missing state=%q", got.State)
		}
	})
}

func TestNativeCampaignProtocolAndEvidenceLimits(t *testing.T) {
	t.Run("bad_fence_frame", func(t *testing.T) {
		f := newT4AFixture(t, "protocol-bad")
		campaign := f.queuedCampaign("protocol-bad")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		run := f.activeRun(*campaign.CurrentAttemptID)
		runner := f.factory.Last()
		runner.onControl = func(c t4aFakeRunnerControl) {
			if c.control.Action == "cancel" {
				c.runner.Deliver(t4aFinalFor(run, "failed", t4aVerifiedCleanup()))
			}
		}
		runner.SendEvent(nativeCampaignRunnerEvent{
			RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
			FencingToken: run.fencingToken + 1, Kind: "event", Observation: json.RawMessage(`{"event":"phase"}`),
		})
		f.waitFor(t, "protocol bad frame final", func() bool { return f.manager.ActiveCount() == 0 })
		got := f.reloadCampaign(campaign)
		if got.State != "failed" {
			t.Fatalf("protocol violation state=%q", got.State)
		}
		if !runner.HasControl("cancel") {
			t.Fatal("protocol violation did not cancel the runner")
		}
	})
	t.Run("evidence_total_cap", func(t *testing.T) {
		f := newT4AFixture(t, "protocol-cap")
		campaign := f.queuedCampaign("protocol-cap")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		run := f.activeRun(*campaign.CurrentAttemptID)
		runner := f.factory.Last()
		runner.onControl = func(c t4aFakeRunnerControl) {
			if c.control.Action == "cancel" {
				c.runner.Deliver(t4aFinalFor(run, "failed", t4aVerifiedCleanup()))
			}
		}
		pad := strings.Repeat("a", (1<<20)-64)
		for i := 0; i < 9; i++ {
			observation, _ := json.Marshal(map[string]any{"event": "phase", "pad": pad})
			runner.SendEvent(nativeCampaignRunnerEvent{
				RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
				FencingToken: run.fencingToken, Kind: "event", Observation: observation,
			})
		}
		f.waitFor(t, "evidence cap final", func() bool { return f.manager.ActiveCount() == 0 })
		got := f.reloadCampaign(campaign)
		if got.State != "failed" {
			t.Fatalf("evidence cap state=%q", got.State)
		}
	})
}

func TestNativeCampaignDeadlineNotExtendedByRenewal(t *testing.T) {
	f := newT4AFixture(t, "deadline")
	campaign := f.queuedCampaign("deadline")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	deadline := run.deadline.ExecutionDeadline
	runner.onControl = func(c t4aFakeRunnerControl) {
		if c.control.Action == "cancel" {
			c.runner.Deliver(t4aFinalFor(run, "timeout", t4aVerifiedCleanup()))
		}
	}
	if err := f.manager.StepLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !run.deadline.ExecutionDeadline.Equal(deadline) {
		t.Fatalf("renewal moved execution deadline: %s -> %s", deadline, run.deadline.ExecutionDeadline)
	}
	f.clock.Set(deadline.Add(time.Second))
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "deadline final", func() bool { return f.manager.ActiveCount() == 0 })
	got := f.reloadCampaign(campaign)
	if got.State != "completed" || got.TerminationReason == nil || *got.TerminationReason != "budget_exhausted" {
		t.Fatalf("deadline campaign=%+v", got)
	}
	start, _, _, _ := runner.Snapshot()
	if start.ExecutionDeadline != deadline.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("runner deadline=%q want=%q", start.ExecutionDeadline, deadline.UTC().Format(time.RFC3339Nano))
	}
}

func TestNativeCampaignCloseBoundedNoLeak(t *testing.T) {
	f := newT4AFixture(t, "close")
	campaign := f.queuedCampaign("close")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	if run == nil {
		t.Fatal("run is nil")
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := f.manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 4*time.Second {
		t.Fatalf("Close took too long: %s", elapsed)
	}
	if f.manager.ActiveCount() != 0 {
		t.Fatalf("Close leaked active runs: %d", f.manager.ActiveCount())
	}
	select {
	case <-run.done:
	default:
		t.Fatal("run.done was not closed")
	}
	runner := f.factory.Last()
	if !runner.HasControl("cancel") {
		t.Fatal("Close did not cancel its runner")
	}
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != "interrupted" || !attempt.ResourceHold || attempt.CleanupStatus != "unknown" {
		t.Fatalf("Close attempt=%+v", attempt)
	}
}

func TestNativeCampaignStartupReconciliation(t *testing.T) {
	f := newT4AFixture(t, "reconcile")
	campaign := f.queuedCampaign("reconcile")
	outcome, err := f.service.Claim(context.Background(), f.task.ID, campaign.ID, "reconcile-claim")
	if err != nil {
		t.Fatal(err)
	}
	if outcome == nil || outcome.Claim == nil {
		t.Fatal("manual claim failed")
	}
	err = f.manager.Start(context.Background())
	if !errors.Is(err, ErrNativeCampaignReconciliationRequired) {
		t.Fatalf("Start err=%v want reconciliation", err)
	}
	if !f.manager.NeedsReconciliation() {
		t.Fatal("manager did not record reconciliation requirement")
	}
	if f.factory.Count() != 0 {
		t.Fatalf("factory started during reconciliation: %d", f.factory.Count())
	}
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, outcome.Claim.Attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !attempt.ResourceHold || attempt.State == "failed" {
		t.Fatalf("reconciliation released/changed the hold: %+v", attempt)
	}
}

func TestNativeCampaignResumeNewAttemptUsesDurableSpecBudget(t *testing.T) {
	f := newT4AFixture(t, "resume-budget")
	f.useRealCheckpointStore()
	campaign := f.queuedCampaign("resume-budget")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "first attempt", func() bool { return f.factory.Count() == 1 })
	campaign = f.reloadCampaign(campaign)
	firstAttemptID := *campaign.CurrentAttemptID
	if _, err := f.service.Pause(context.Background(), f.task.ID, campaign.ID, "test pause", "t4a-resume-pause"); err != nil {
		t.Fatalf("pause before paused final: %v", err)
	}
	f.driveFinal(t, firstAttemptID, "paused", t4aVerifiedCleanup())
	paused := f.reloadCampaign(campaign)
	if paused.State != "paused" || paused.LatestCheckpointID == nil || paused.CleanupStatus != "verified" {
		t.Fatalf("paused campaign=%+v", paused)
	}
	if f.checkpoint.Calls() != 1 {
		t.Fatalf("checkpoint sink calls=%d", f.checkpoint.Calls())
	}
	resp, err := f.service.Resume(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: paused.ID,
		RequestID:            fmt.Sprintf("t4a-resume-%d", paused.ID),
		ExpectedStateVersion: paused.StateVersion, ActorKind: "admin",
	})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if resp.Status != 202 {
		t.Fatalf("resume status=%d", resp.Status)
	}
	queued := f.reloadCampaign(paused)
	if queued.State != "queued" || queued.DesiredState != "running" {
		t.Fatalf("resume did not only queue: %+v", queued)
	}
	if f.factory.Count() != 1 {
		t.Fatalf("resume started a runner synchronously: %d", f.factory.Count())
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "second attempt", func() bool { return f.factory.Count() == 2 })
	restoredStart, _, _, _ := f.factory.Last().Snapshot()
	if len(restoredStart.Seeds) != 1 || restoredStart.Seeds[0].DataBase64 != "cmVzdG9yZWQ=" || restoredStart.Seeds[0].SHA256 != t4aHash("restored") || restoredStart.Seeds[0].DataBase64 == "Wg==" {
		t.Fatalf("resume did not use actual checkpoint bytes instead of initial seeds: %+v", restoredStart.Seeds)
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts=%d want 2", len(attempts))
	}
	second := attempts[0]
	if second.AttemptNo != 2 || second.ReservedBudgetMS != 60000 {
		t.Fatalf("second attempt budget was overridden: %+v", second)
	}
	if second.StartedAt == nil {
		t.Fatal("second attempt started_at was not persisted")
	}
}

func TestNativeCampaignWatcherSignals(t *testing.T) {
	t.Run("profile_disable_pauses_no_auto_resume", func(t *testing.T) {
		f := newT4AFixture(t, "watch-profile")
		campaign := f.queuedCampaign("watch-profile")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		run := f.activeRun(*campaign.CurrentAttemptID)
		runner := f.factory.Last()
		watched := f.profile
		f.service.profiles = func() ([]reverseRuntimeProfile, error) {
			return []reverseRuntimeProfile{watched}, nil
		}
		watched.Settings["enabled"] = false
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		stopping := f.reloadCampaign(campaign)
		if stopping.State != "stopping" || stopping.DesiredState != "paused" {
			t.Fatalf("profile disable did not pause: %+v", stopping)
		}
		_, _, controlsBefore, _ := runner.Snapshot()
		watched.Settings["enabled"] = true
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		_, _, controlsAfter, _ := runner.Snapshot()
		if len(controlsAfter) != len(controlsBefore) {
			t.Fatalf("profile re-enable sent a new control: before=%v after=%v", controlsBefore, controlsAfter)
		}
		still := f.reloadCampaign(campaign)
		if still.State != "stopping" || still.DesiredState != "paused" {
			t.Fatalf("profile re-enable auto-resumed: %+v", still)
		}
		// Finish the pause normally; a later re-enable must still not resume.
		runner.onControl = func(c t4aFakeRunnerControl) {}
		runner.mu.Lock()
		runner.cleanup = t4aVerifiedCleanup()
		runner.mu.Unlock()
		runner.Deliver(t4aFinalFor(run, "paused", t4aVerifiedCleanup()))
		f.waitFor(t, "paused final", func() bool { return f.manager.ActiveCount() == 0 })
		paused := f.reloadCampaign(campaign)
		if paused.State != "paused" {
			t.Fatalf("pause final state=%q", paused.State)
		}
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		after := f.reloadCampaign(campaign)
		if after.State != "paused" {
			t.Fatalf("re-enabled paused campaign auto-resumed: %+v", after)
		}
	})
	t.Run("task_terminal_cancels", func(t *testing.T) {
		f := newT4AFixture(t, "watch-terminal")
		campaign := f.queuedCampaign("watch-terminal")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		run := f.activeRun(*campaign.CurrentAttemptID)
		runner := f.factory.Last()
		runner.onControl = func(c t4aFakeRunnerControl) {
			if c.control.Action == "cancel" {
				c.runner.Deliver(t4aFinalFor(run, "cancelled", t4aVerifiedCleanup()))
			}
		}
		if _, err := f.pg.Exec(`UPDATE tasks SET status='done' WHERE id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "terminal cancel", func() bool { return f.manager.ActiveCount() == 0 })
		got := f.reloadCampaign(campaign)
		if got.State != "cancelled" {
			t.Fatalf("terminal task campaign=%+v", got)
		}
	})
	t.Run("policy_revision_cancels", func(t *testing.T) {
		f := newT4AFixture(t, "watch-policy")
		campaign := f.queuedCampaign("watch-policy")
		f.startManager()
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
		campaign = f.reloadCampaign(campaign)
		run := f.activeRun(*campaign.CurrentAttemptID)
		runner := f.factory.Last()
		runner.onControl = func(c t4aFakeRunnerControl) {
			if c.control.Action == "cancel" {
				c.runner.Deliver(t4aFinalFor(run, "cancelled", t4aVerifiedCleanup()))
			}
		}
		if _, err := f.pg.Exec(`UPDATE reverse_runtime_policies SET revision=revision+1 WHERE task_id=$1`, f.task.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.manager.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		f.waitFor(t, "policy revocation cancel", func() bool { return f.manager.ActiveCount() == 0 })
		got := f.reloadCampaign(campaign)
		if got.State != "cancelled" {
			t.Fatalf("policy revocation campaign=%+v", got)
		}
	})
}

func TestNativeCampaignLeaseLocalTTLStop(t *testing.T) {
	f := newT4AFixture(t, "lease-ttl")
	campaign := f.queuedCampaign("lease-ttl")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	f.clock.Set(run.leaseExpires.Add(time.Second))
	if err := f.manager.StepLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "local TTL stop", func() bool { return f.manager.ActiveCount() == 0 })
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != "interrupted" || !attempt.ResourceHold {
		t.Fatalf("local TTL attempt=%+v", attempt)
	}
}

func TestNativeCampaignRunnerEOFSafeStop(t *testing.T) {
	f := newT4AFixture(t, "eof")
	campaign := f.queuedCampaign("eof")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	runner.onControl = func(c t4aFakeRunnerControl) {
		if c.control.Action == "cancel" {
			c.runner.Deliver(t4aFinalFor(run, "failed", t4aVerifiedCleanup()))
		}
	}
	runner.CloseEvents()
	f.waitFor(t, "EOF stop", func() bool { return f.manager.ActiveCount() == 0 })
	if !runner.HasControl("cancel") {
		t.Fatal("EOF did not safely cancel the runner")
	}
	got := f.reloadCampaign(campaign)
	if got.State != "failed" {
		t.Fatalf("EOF campaign state=%q", got.State)
	}
}

type t4aFailingHaltLeaseStore struct {
	nativeCampaignLeaseStore
}

func (s t4aFailingHaltLeaseStore) HaltNativeCampaignAttemptForLeaseLoss(context.Context, db.NativeCampaignLeaseHaltCommand) (*db.NativeCampaignLeaseResult, error) {
	return nil, errors.New("synthetic database unavailable during halt")
}

func TestNativeCampaignLeaseDBLossDoesNotClaimCleanup(t *testing.T) {
	f := newT4AFixture(t, "lease-db-loss")
	campaign := f.queuedCampaign("lease-db-loss")
	base := nativeCampaignDBLeaseStore{pg: f.pg}
	manager, err := newNativeCampaignManager(nativeCampaignManagerConfig{
		Enabled: true, DB: f.pg, Service: f.service, Clock: f.clock,
		RunnerFactory: f.factory.New,
		LeaseStore:    t4aFailingHaltLeaseStore{nativeCampaignLeaseStore: base},
		StopTimeout:   3 * time.Second, CleanupTimeout: 3 * time.Second, ControlTimeout: 2 * time.Second,
		DisableBackground: true, InstanceID: "t4a-lease-db-loss",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	if err := manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	if _, err := f.pg.Exec(`UPDATE native_campaign_attempts SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND campaign_id=$2`, f.task.ID, campaign.ID); err != nil {
		t.Fatal(err)
	}
	_ = manager.StepLeases(context.Background())
	f.waitFor(t, "db-loss stop", func() bool { return manager.ActiveCount() == 0 })
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, *campaign.CurrentAttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.CleanupStatus == "verified" || !attempt.ResourceHold {
		t.Fatalf("DB outage was locally reported as verified cleanup: %+v", attempt)
	}
	// The runner was stopped; the DB row still carries the unconfirmed hold for
	// reconciliation because the halt transaction could not commit.
	runner := f.factory.Last()
	if !runner.HasControl("cancel") {
		t.Fatal("DB-loss stop did not cancel the runner")
	}
}

// final_then_close and close_then_final are both legal producer termination
// orders. Wait success is not proof that Events is exhausted: the manager must
// boundedly drain trailing frames and reject a bad one instead of requiring the
// old close-after-Wait ordering.
func TestNativeCampaignRunnerCompletionOrders(t *testing.T) {
	t.Run("final_then_close", func(t *testing.T) {
		f := newT4AFixture(t, "order-final-close")
		campaign, run := f.startOneRun(t, "order-final-close")
		f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "final then close", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State != "completed" {
			t.Fatalf("final-then-close campaign=%+v", got)
		}
		run.mu.Lock()
		eventsClosed := run.eventsClosed
		run.mu.Unlock()
		if !eventsClosed {
			t.Fatal("final-then-close did not record Events close")
		}
	})
	t.Run("close_then_final", func(t *testing.T) {
		f := newT4AFixture(t, "order-close-final")
		campaign, run := f.startOneRun(t, "order-close-final")
		runner := f.factory.Last()
		runner.CloseEvents()
		runner.DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "close then final", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State != "completed" {
			t.Fatalf("close-then-final campaign=%+v", got)
		}
		run.mu.Lock()
		eventsClosed := run.eventsClosed
		run.mu.Unlock()
		if !eventsClosed {
			t.Fatal("close-then-final did not record Events close")
		}
	})
	t.Run("final_without_event_close_bounded", func(t *testing.T) {
		f := newT4AFixture(t, "order-final-open")
		campaign, run := f.startOneRun(t, "order-final-open")
		f.manager.drainTimeout = 100 * time.Millisecond
		f.factory.Last().DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "bounded drain final", func() bool { return f.manager.ActiveCount() == 0 })
		got := f.reloadCampaign(campaign)
		if got.State == "completed" || got.State == "paused" {
			t.Fatalf("unclosed event stream was accepted as success: %+v", got)
		}
		if got.State != "failed" {
			t.Fatalf("unclosed event stream state=%q want failed", got.State)
		}
		run.mu.Lock()
		truncated := run.drainTruncated
		timedOut := run.drainTimedOut
		eventsClosed := run.eventsClosed
		run.mu.Unlock()
		if !truncated || !timedOut || eventsClosed {
			t.Fatalf("drain flags truncated=%v timedOut=%v eventsClosed=%v", truncated, timedOut, eventsClosed)
		}
		observation := string(f.storage.LastObservation())
		if !strings.Contains(observation, `"drain_timed_out":true`) {
			t.Fatalf("evidence did not record drain_timed_out: %s", observation)
		}
	})
	t.Run("late_bad_tail_without_close", func(t *testing.T) {
		f := newT4AFixture(t, "order-late-bad")
		campaign, run := f.startOneRun(t, "order-late-bad")
		f.manager.drainTimeout = 200 * time.Millisecond
		runner := f.factory.Last()
		runner.mu.Lock()
		runner.afterWait = func() {
			runner.SendEvent(nativeCampaignRunnerEvent{
				RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
				FencingToken: run.fencingToken + 1, Kind: "event",
				Observation: json.RawMessage(`{"event":"late"}`),
			})
		}
		runner.mu.Unlock()
		runner.DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "late bad tail drain", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State != "failed" {
			t.Fatalf("late bad tail was not rejected: %+v", got)
		}
	})
	t.Run("late_oversize_tail_without_close", func(t *testing.T) {
		f := newT4AFixture(t, "order-late-oversize")
		campaign, run := f.startOneRun(t, "order-late-oversize")
		f.manager.drainTimeout = 200 * time.Millisecond
		runner := f.factory.Last()
		oversize, err := json.Marshal(map[string]any{"pad": strings.Repeat("a", (1<<20)+64)})
		if err != nil {
			t.Fatal(err)
		}
		runner.mu.Lock()
		runner.afterWait = func() {
			runner.SendEvent(nativeCampaignRunnerEvent{
				RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
				FencingToken: run.fencingToken, Kind: "event", Observation: oversize,
			})
		}
		runner.mu.Unlock()
		runner.DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "late oversize tail drain", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State != "failed" {
			t.Fatalf("oversize tail was not rejected: %+v", got)
		}
	})
	t.Run("timer_and_bad_tail_ready_fails_closed", func(t *testing.T) {
		f := newT4AFixture(t, "order-timer-bad")
		campaign, run := f.startOneRun(t, "order-timer-bad")
		f.manager.drainTimeout = time.Nanosecond
		runner := f.factory.Last()
		runner.mu.Lock()
		runner.afterWait = func() {
			runner.SendEvent(nativeCampaignRunnerEvent{
				RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
				FencingToken: run.fencingToken + 1, Kind: "event",
				Observation: json.RawMessage(`{"event":"tie"}`),
			})
		}
		runner.mu.Unlock()
		runner.DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "timer/bad tie drain", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State == "completed" || got.State == "paused" || got.State != "failed" {
			t.Fatalf("timer/bad tie produced %+v", got)
		}
	})
	t.Run("bad_tail_frame_after_wait", func(t *testing.T) {
		f := newT4AFixture(t, "order-bad-tail")
		campaign, run := f.startOneRun(t, "order-bad-tail")
		runner := f.factory.Last()
		runner.mu.Lock()
		runner.afterWait = func() {
			runner.SendEvent(nativeCampaignRunnerEvent{
				RequestID: run.expectation().RequestID, AttemptID: run.attemptID,
				FencingToken: run.fencingToken + 1, Kind: "event",
				Observation: json.RawMessage(`{"event":"phase"}`),
			})
			runner.CloseEvents()
		}
		runner.mu.Unlock()
		runner.DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		f.waitFor(t, "bad tail final", func() bool { return f.manager.ActiveCount() == 0 })
		if got := f.reloadCampaign(campaign); got.State != "failed" {
			t.Fatalf("bad tail frame was not rejected: %+v", got)
		}
	})
}

// EOF without a final must end through a bounded cancel/Wait/cleanup path. If it
// ever fails to stop, save all goroutine stacks so the next reviewer can tell a
// deadlock from a slow cleanup instead of inferring it from a bare RUN line.
func TestNativeCampaignRunnerEOFBoundedStack(t *testing.T) {
	f := newT4AFixture(t, "eof-bounded")
	campaign := f.queuedCampaign("eof-bounded")
	f.manager.eofTimeout = 100 * time.Millisecond
	f.manager.stopTimeout = 400 * time.Millisecond
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	runner.CloseEvents()
	deadline := time.Now().Add(3 * time.Second)
	for f.manager.ActiveCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.manager.ActiveCount() != 0 {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		path := filepath.Join(t.TempDir(), "eof-goroutines.txt")
		_ = os.WriteFile(path, stack[:n], 0o600)
		t.Fatalf("EOF did not stop boundedly; goroutine stacks saved to %s\n%s", path, stack[:n])
	}
	if !runner.HasControl("cancel") {
		t.Fatal("EOF did not issue a bounded cancel")
	}
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("EOF attempt=%+v", attempt)
	}
}

func TestNativeCampaignCancelTransitionConflictsAndFreshRequestID(t *testing.T) {
	f := newT4AFixture(t, "cancel-conflict")
	campaign, run := f.startOneRun(t, "cancel-conflict")
	runner := f.factory.Last()
	var bumps atomic.Int64
	injectConflict := func() {
		if bumps.Add(1) == 1 {
			if _, err := f.pg.Exec(`UPDATE native_campaigns SET state_version=state_version+1
				WHERE task_id=$1 AND id=$2`, f.task.ID, campaign.ID); err != nil {
				t.Errorf("inject state conflict: %v", err)
			}
		}
	}
	f.service.beforeStateMutation = injectConflict
	if _, err := f.pg.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatalf("pause with injected conflict: %v", err)
	}
	f.waitFor(t, "pause retried to DB", func() bool {
		got := f.reloadCampaign(campaign)
		return got.State == "stopping" && got.DesiredState == "paused"
	})
	if !runner.HasControl("pause") {
		t.Fatal("pause was not ACKed after the conflict retry confirmed the DB")
	}
	if ids := t4aDistinctRequestIDs(t, f, "pause"); ids < 2 {
		t.Fatalf("pause conflict retry reused a stale request_id: distinct=%d", ids)
	}

	bumps.Store(0)
	// The task pause that produced the pause request must be lifted before the
	// policy revocation, otherwise task_paused keeps winning before the watcher
	// can evaluate the higher-priority cancel signal.
	if _, err := f.pg.Exec(`UPDATE tasks SET paused=false WHERE id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	runner.onControl = func(c t4aFakeRunnerControl) {
		if c.control.Action == "cancel" {
			c.runner.Deliver(t4aFinalFor(run, "cancelled", t4aVerifiedCleanup()))
		}
	}
	// Revoke the policy rather than deleting the task: the deterministic 409
	// response is cached only while the task row still exists, which is exactly
	// what a later retry must not collide with.
	if _, err := f.pg.Exec(`UPDATE reverse_runtime_policies SET revision=revision+1 WHERE task_id=$1`, f.task.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatalf("cancel with injected conflict: %v", err)
	}
	f.waitFor(t, "cancel retried to DB", func() bool {
		got := f.reloadCampaign(campaign)
		return got.State == "cancelled"
	})
	if ids := t4aDistinctRequestIDs(t, f, "cancel"); ids < 2 {
		rows, _ := f.pg.Query(`SELECT request_id,response_status,response_body::text
			FROM native_campaign_requests WHERE task_id=$1 AND action='cancel' ORDER BY id`, f.task.ID)
		var dump []string
		if rows != nil {
			for rows.Next() {
				var id, body string
				var status int
				_ = rows.Scan(&id, &status, &body)
				dump = append(dump, fmt.Sprintf("%s status=%d body=%s", id, status, body))
			}
			rows.Close()
		}
		t.Fatalf("cancel conflict retry reused a stale request_id: distinct=%d rows=%v", ids, dump)
	}
}

// A campaign that actually reached paused is not a successful cancel. The
// cancel must still be written to the database and only then acknowledged.
func TestNativeCampaignCancelFromActualPausedMutatesDB(t *testing.T) {
	f := newT4AFixture(t, "cancel-paused")
	campaign, run := f.startOneRun(t, "cancel-paused")
	runner := f.factory.Last()
	if _, err := f.service.Pause(context.Background(), f.task.ID, campaign.ID, "pause first", "cancel-paused-pause"); err != nil {
		t.Fatal(err)
	}
	runner.Deliver(t4aFinalFor(run, "paused", t4aVerifiedCleanup()))
	f.waitFor(t, "paused final", func() bool { return f.manager.ActiveCount() == 0 })
	paused := f.reloadCampaign(campaign)
	if paused.State != "paused" || paused.LatestCheckpointID == nil {
		t.Fatalf("paused precondition=%+v", paused)
	}
	synthetic := &nativeCampaignRun{
		taskID: f.task.ID, campaignID: paused.ID, attemptID: *paused.CurrentAttemptID,
		fencingToken: run.fencingToken, leaseOwner: run.leaseOwner, leaseInstance: run.leaseInstance,
		lifecycle: nativeCampaignRunRunning, requestedState: "pause", requestedConfirmed: true,
	}
	if err := f.manager.transitionCampaign(context.Background(), synthetic, "cancel", "cancel paused"); err != nil {
		t.Fatalf("cancel from actual paused: %v", err)
	}
	got := f.reloadCampaign(paused)
	if got.State != "cancelled" {
		t.Fatalf("actual paused was treated as cancel success without a DB mutation: %+v", got)
	}
	if ids := t4aDistinctRequestIDs(t, f, "cancel"); ids < 1 {
		t.Fatal("cancel from paused did not persist a cancel request")
	}
}

func t4aDistinctRequestIDs(t *testing.T, f *t4aFixture, action string) int {
	t.Helper()
	var count int
	if err := f.pg.QueryRow(`SELECT count(DISTINCT request_id) FROM native_campaign_requests
		WHERE task_id=$1 AND action=$2`, f.task.ID, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestNativeCampaignResumeNilBudgetUsesSpecDefaultCurrentCap(t *testing.T) {
	f := newT4AFixture(t, "resume-nil-budget")
	f.useRealCheckpointStore()
	campaign := f.createCampaignWithSpec("resume-nil-budget", 61000, 10000)
	campaign = f.startWithBudget(campaign, 60000)
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "first attempt", func() bool { return f.factory.Count() == 1 })
	campaign = f.reloadCampaign(campaign)
	firstAttemptID := *campaign.CurrentAttemptID
	if _, err := f.service.Pause(context.Background(), f.task.ID, campaign.ID, "pause before resume", "resume-nil-pause"); err != nil {
		t.Fatal(err)
	}
	f.driveFinal(t, firstAttemptID, "paused", t4aVerifiedCleanup())
	paused := f.reloadCampaign(campaign)
	if paused.State != "paused" || paused.LatestCheckpointID == nil {
		t.Fatalf("paused campaign=%+v", paused)
	}
	// remaining = 61000-10000 = 51000, below the previous explicit 60000 cap
	// but above the immutable spec default of 10000.
	if _, err := f.pg.Exec(`UPDATE native_campaigns SET charged_budget_ms=10000
		WHERE task_id=$1 AND id=$2`, f.task.ID, paused.ID); err != nil {
		t.Fatal(err)
	}
	resp, err := f.service.Resume(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: paused.ID,
		RequestID:            fmt.Sprintf("t4a-resume-nil-%d", paused.ID),
		ExpectedStateVersion: paused.StateVersion, ActorKind: "admin",
	})
	if err != nil {
		t.Fatalf("nil-budget resume inherited the previous explicit cap: %v", err)
	}
	if resp.Status != 202 {
		t.Fatalf("resume status=%d", resp.Status)
	}
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "second attempt", func() bool { return f.factory.Count() == 2 })
	restoredStart, _, _, _ := f.factory.Last().Snapshot()
	if len(restoredStart.Seeds) != 1 || restoredStart.Seeds[0].DataBase64 != "cmVzdG9yZWQ=" || restoredStart.Seeds[0].SHA256 != t4aHash("restored") || restoredStart.Seeds[0].DataBase64 == "Wg==" {
		t.Fatalf("resume did not use actual checkpoint bytes instead of initial seeds: %+v", restoredStart.Seeds)
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, paused.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var second db.NativeCampaignAttempt
	foundSecond := false
	for _, attempt := range attempts {
		if attempt.AttemptNo == 2 {
			second = attempt
			foundSecond = true
		}
	}
	if !foundSecond || second.ReservedBudgetMS != 10000 {
		t.Fatalf("second attempt budget=%+v want reserved 10000", second)
	}
	var capRaw *string
	if err := f.pg.QueryRow(`SELECT payload->>'attempt_budget_ms' FROM native_campaign_events
		WHERE task_id=$1 AND campaign_id=$2 AND kind='campaign.resume_queued'
		ORDER BY id DESC LIMIT 1`, f.task.ID, paused.ID).Scan(&capRaw); err != nil {
		t.Fatal(err)
	}
	if capRaw != nil {
		t.Fatalf("nil resume persisted a stale explicit cap: %q", *capRaw)
	}
}

func TestNativeCampaignFactoryGatedByPauseCancel(t *testing.T) {
	for _, action := range []string{"pause", "cancel"} {
		t.Run(action, func(t *testing.T) {
			f := newT4AFixture(t, "factory-gate-"+action)
			campaign := f.queuedCampaign("factory-gate-" + action)
			entered := make(chan struct{})
			release := make(chan struct{})
			f.factory.hook = func(*t4aFakeRunner) {
				close(entered)
				<-release
			}
			f.startManager()
			stepErr := make(chan error, 1)
			go func() { stepErr <- f.manager.Step(context.Background()) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("factory was not entered")
			}
			campaign = f.reloadCampaign(campaign)
			var err error
			switch action {
			case "pause":
				_, err = f.service.Pause(context.Background(), f.task.ID, campaign.ID, "factory gate", "factory-gate-pause")
			case "cancel":
				_, err = f.service.Cancel(context.Background(), f.task.ID, campaign.ID, "factory gate", "factory-gate-cancel")
			}
			if err != nil {
				t.Fatalf("%s while factory blocked: %v", action, err)
			}
			close(release)
			select {
			case <-stepErr:
			case <-time.After(5 * time.Second):
				t.Fatal("Step did not return after factory release")
			}
			runner := f.factory.Last()
			if runner == nil {
				t.Fatal("factory did not produce a runner")
			}
			_, started, _, _ := runner.Snapshot()
			if started {
				t.Fatalf("%s during factory still started the runner", action)
			}
			if f.manager.ActiveCount() != 0 {
				t.Fatalf("gated start leaked an active run: %d", f.manager.ActiveCount())
			}
			attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(attempts) != 1 || attempts[0].State == "running" || attempts[0].State == "launching" || attempts[0].State == "claimed" {
				t.Fatalf("gated attempt=%+v", attempts)
			}
		})
	}
}

func TestNativeCampaignStartContextEarliestDeadline(t *testing.T) {
	base := time.Unix(1700000000, 0)
	cases := []struct {
		name      string
		execution time.Time
		envelope  time.Time
		lease     time.Time
		want      time.Time
		startable bool
	}{
		{name: "start_timeout", execution: base.Add(20 * time.Second), envelope: base.Add(30 * time.Second), lease: base.Add(40 * time.Second), want: base.Add(10 * time.Second), startable: true},
		{name: "execution", execution: base.Add(5 * time.Second), envelope: base.Add(30 * time.Second), lease: base.Add(40 * time.Second), want: base.Add(5 * time.Second), startable: true},
		{name: "envelope", execution: base.Add(20 * time.Second), envelope: base.Add(3 * time.Second), lease: base.Add(40 * time.Second), want: base.Add(3 * time.Second), startable: true},
		{name: "lease", execution: base.Add(20 * time.Second), envelope: base.Add(30 * time.Second), lease: base.Add(2 * time.Second), want: base.Add(2 * time.Second), startable: true},
		{name: "expired", execution: base.Add(-time.Second), envelope: base.Add(30 * time.Second), lease: base.Add(40 * time.Second), want: base.Add(-time.Second), startable: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := nativeCampaignEarliestStartDeadline(base, 10*time.Second, tc.execution, tc.envelope, tc.lease)
			if ok != tc.startable || !got.Equal(tc.want) {
				t.Fatalf("deadline=%s ok=%v want=%s startable=%v", got, ok, tc.want, tc.startable)
			}
		})
	}

	f := newT4AFixture(t, "start-context")
	f.manager.startTimeout = 2 * time.Second
	campaign, run := f.startOneRun(t, "start-context")
	runner := f.factory.Last()
	deadline, ctxErr := runner.StartContext()
	if ctxErr != nil || deadline.IsZero() {
		t.Fatalf("Start ctx deadline=%s err=%v", deadline, ctxErr)
	}
	remaining := time.Until(deadline)
	if remaining < time.Second || remaining > 3*time.Second {
		t.Fatalf("Start ctx did not use the startTimeout branch: remaining=%s", remaining)
	}
	if deadline.After(run.deadline.ExecutionDeadline) || deadline.After(run.deadline.EnvelopeDeadline) {
		t.Fatalf("Start ctx deadline %s exceeds an absolute attempt deadline", deadline)
	}
	run.mu.Lock()
	lease := run.leaseExpires
	run.mu.Unlock()
	if !lease.IsZero() && deadline.After(lease) {
		t.Fatalf("Start ctx deadline %s exceeds the lease deadline %s", deadline, lease)
	}
	_ = campaign
}

func TestNativeCampaignStartCloseRace(t *testing.T) {
	f := newT4AFixture(t, "start-close-race")
	campaign := f.queuedCampaign("start-close-race")
	entered := make(chan struct{})
	release := make(chan struct{})
	f.manager.beforeStartHook = func() {
		close(entered)
		<-release
	}
	f.startManager()
	stepErr := make(chan error, 1)
	go func() { stepErr <- f.manager.Step(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("start path did not reach the registered lifecycle")
	}
	if f.manager.ActiveCount() != 1 {
		t.Fatalf("run was not registered before Start: active=%d", f.manager.ActiveCount())
	}
	closeErrCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		closeErrCh <- f.manager.Close(ctx)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.manager.mu.Lock()
		closed := f.manager.closed
		f.manager.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not begin")
		}
		time.Sleep(2 * time.Millisecond)
	}
	select {
	case err := <-closeErrCh:
		t.Fatalf("Close returned before the registered start path finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-stepErr:
	case <-time.After(5 * time.Second):
		t.Fatal("start path did not finish after release")
	}
	closeErr := <-closeErrCh
	if closeErr != nil && !errors.Is(closeErr, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("unexpected Close error: %v", closeErr)
	}
	runner := f.factory.Last()
	if runner == nil {
		t.Fatal("factory did not produce a runner")
	}
	if _, started, _, _ := runner.Snapshot(); started {
		t.Fatal("Start was called after Close won the registration race")
	}
	if f.manager.ActiveCount() != 0 {
		t.Fatalf("active run leaked after Close/Start race: %d", f.manager.ActiveCount())
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || (attempts[0].State != "failed" && attempts[0].State != "interrupted") {
		t.Fatalf("attempt after Close/Start race=%+v", attempts)
	}
}

func TestNativeCampaignConcurrentCloseNoPrematureSuccess(t *testing.T) {
	f := newT4AFixture(t, "concurrent-close")
	f.factory.hook = func(r *t4aFakeRunner) {
		r.mu.Lock()
		r.waitBlock = make(chan struct{})
		r.waitIgnoreCtx = true
		r.waitEntered = make(chan struct{})
		r.mu.Unlock()
	}
	campaign := f.queuedCampaign("concurrent-close")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	runner.mu.Lock()
	waitEntered := runner.waitEntered
	runner.mu.Unlock()
	select {
	case <-waitEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocking Wait was not entered")
	}
	f.manager.stopTimeout = 200 * time.Millisecond
	first := make(chan error, 1)
	go func() { first <- f.manager.Close(context.Background()) }()
	second := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		second <- f.manager.Close(ctx)
	}()
	select {
	case err := <-second:
		t.Fatalf("concurrent second Close returned before the first completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	err1 := <-first
	if !errors.Is(err1, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("first Close err=%v want bounded timeout", err1)
	}
	err2 := <-second
	if !errors.Is(err2, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("second Close err=%v want the shared bounded timeout", err2)
	}
	attempt, err := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("timed-out Close did not retain the unknown-cleanup hold: %+v", attempt)
	}
	runner.mu.Lock()
	block := runner.waitBlock
	runner.mu.Unlock()
	close(block)
	select {
	case <-run.done:
	case <-time.After(3 * time.Second):
		t.Fatal("run.done did not close after the non-cooperative Wait was released")
	}
}

// Exact assertions from the supervisor's independent counterexamples. They are
// kept as first-class tests so a broad pass count can never hide them again.
func TestNativeCampaignReviewUnclosedEventsNeverSucceed(t *testing.T) {
	f := newT4AFixture(t, "review-open-events")
	f.manager.drainTimeout = 50 * time.Millisecond
	campaign, run := f.startOneRun(t, "review-open-events")
	f.factory.Last().DeliverFinalOnly(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
	f.waitFor(t, "drain completion", func() bool { return f.manager.ActiveCount() == 0 })
	if got := f.reloadCampaign(campaign); got.State == "completed" || got.State == "paused" {
		t.Fatalf("unclosed event stream accepted as success: state=%s", got.State)
	}
}

func TestNativeCampaignReviewCloseTracksFactory(t *testing.T) {
	f := newT4AFixture(t, "review-factory-close")
	f.queuedCampaign("review-factory-close")
	entered := make(chan struct{})
	release := make(chan struct{})
	stepDone := make(chan error, 1)
	f.factory.hook = func(*t4aFakeRunner) {
		close(entered)
		<-release
	}
	f.startManager()
	go func() { stepDone <- f.manager.Step(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("factory not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := f.manager.Close(ctx)
	close(release)
	select {
	case <-stepDone:
	case <-time.After(5 * time.Second):
		t.Fatal("step failed to settle")
	}
	if err == nil {
		t.Fatal("Close reported success while factory was still blocked")
	}
}

// A lease/EOF abort can remove the business-active run while its Wait goroutine
// ignores ctx. A later Close has an empty active map but must still track the
// transport and return an explicit bounded error.
func TestNativeCampaignAbortThenCloseTracksBlockedWait(t *testing.T) {
	f := newT4AFixture(t, "abort-then-close")
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseWait := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWait)
	f.factory.hook = func(r *t4aFakeRunner) {
		r.mu.Lock()
		r.waitBlock = release
		r.waitIgnoreCtx = true
		r.waitEntered = make(chan struct{})
		r.mu.Unlock()
	}
	campaign := f.queuedCampaign("abort-then-close")
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "active run", func() bool { return f.manager.ActiveCount() == 1 })
	campaign = f.reloadCampaign(campaign)
	run := f.activeRun(*campaign.CurrentAttemptID)
	runner := f.factory.Last()
	runner.mu.Lock()
	waitEntered := runner.waitEntered
	runner.mu.Unlock()
	select {
	case <-waitEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("blocking Wait was not entered")
	}
	// Force the manager-side lease-loss abort first; it removes active before
	// the non-cooperative Wait exits.
	f.clock.Set(run.leaseExpires.Add(time.Second))
	if err := f.manager.StepLeases(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitFor(t, "aborted active", func() bool { return f.manager.ActiveCount() == 0 })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := f.manager.Close(ctx); err == nil {
		t.Fatal("Close reported success with an aborted but still blocked Wait")
	}
	releaseWait()
	select {
	case <-run.transportDone:
	case <-time.After(3 * time.Second):
		t.Fatal("transport was not released after the blocked Wait returned")
	}
}

// Factory time must not buy a fresh StartTimeout: the final deadline is capped
// by the original overall deadline, not just freshly derived boundaries.
func TestNativeCampaignFactoryTimeDoesNotExtendStartDeadline(t *testing.T) {
	f := newT4AFixture(t, "factory-deadline")
	f.manager.startTimeout = 100 * time.Millisecond
	f.factory.hook = func(*t4aFakeRunner) {
		f.clock.Advance(2 * f.manager.startTimeout)
	}
	campaign := f.queuedCampaign("factory-deadline")
	f.startManager()
	if err := f.manager.Step(context.Background()); err == nil {
		t.Fatal("Step succeeded after the factory consumed the original start deadline")
	}
	if f.factory.Count() != 1 {
		t.Fatalf("factory count=%d want 1", f.factory.Count())
	}
	if _, started, _, _ := f.factory.Last().Snapshot(); started {
		t.Fatal("runner Start was called after the original start deadline elapsed")
	}
	if f.manager.ActiveCount() != 0 {
		t.Fatalf("deadline-expired start leaked active runs: %d", f.manager.ActiveCount())
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || (attempts[0].State != "failed" && attempts[0].State != "interrupted") {
		t.Fatalf("factory-deadline attempt=%+v", attempts)
	}
}

// t4aBlockingCleanupRunner holds the unique finalizer inside Cleanup without
// ignoring its context. Tests release the barrier in a defer so a failing
// assertion cannot leak the finalization goroutine or the fixture.
type t4aBlockingCleanupRunner struct {
	*t4aFakeRunner
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func (r *t4aBlockingCleanupRunner) Cleanup(ctx context.Context, req nativeCampaignCleanupRequest) (nativeCampaignCleanupReport, error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-r.release:
	case <-ctx.Done():
		return nativeCampaignCleanupReport{}, ctx.Err()
	}
	return r.t4aFakeRunner.Cleanup(ctx, req)
}

func (r *t4aBlockingCleanupRunner) Release() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func t4aLifecycleWaitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func t4aLifecycleRequireOpen(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
		t.Fatalf("%s closed prematurely", what)
	default:
	}
}

// t4aInstallBlockingCleanup replaces the manager factory with one that wraps the
// fixture fake runner. The wrapper is visible after Step has returned.
func t4aInstallBlockingCleanup(f *t4aFixture, target **t4aBlockingCleanupRunner) {
	f.manager.factory = func(ctx context.Context, start nativeCampaignRunnerStart) (nativeCampaignRunner, error) {
		base, err := f.factory.New(ctx, start)
		if err != nil || base == nil {
			return base, err
		}
		fake, ok := base.(*t4aFakeRunner)
		if !ok {
			return base, nil
		}
		wrapper := &t4aBlockingCleanupRunner{
			t4aFakeRunner: fake,
			entered:       make(chan struct{}),
			release:       make(chan struct{}),
		}
		*target = wrapper
		return wrapper, nil
	}
}

func t4aLifecycleFinalizing(t *testing.T, run *nativeCampaignRun) (bool, bool) {
	t.Helper()
	run.mu.Lock()
	defer run.mu.Unlock()
	return run.finalizing, run.finalized
}

// A normal final and an external abort race for the single finalization owner.
// The loser must never remove active, mark finalized, or close done early.
func TestNativeCampaignLifecycleSingleFinalOwner(t *testing.T) {
	t.Run("normal_final_wins", func(t *testing.T) {
		f := newT4AFixture(t, "lifecycle-final-wins")
		var wrapped *t4aBlockingCleanupRunner
		t4aInstallBlockingCleanup(f, &wrapped)
		_, run := f.startOneRun(t, "lifecycle-final-wins")
		if wrapped == nil {
			t.Fatal("blocking cleanup runner was not installed")
		}
		defer wrapped.Release()

		f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		t4aLifecycleWaitClosed(t, wrapped.entered, "normal finalizer Cleanup entry")

		abortDone := make(chan struct{})
		go func() {
			defer close(abortDone)
			f.manager.abortRun(run, "audit_external_abort")
		}()
		t4aLifecycleWaitClosed(t, abortDone, "losing external abort return")
		finalizing, finalized := t4aLifecycleFinalizing(t, run)
		if !finalizing || finalized {
			t.Fatalf("loser changed finalization state: finalizing=%v finalized=%v", finalizing, finalized)
		}
		if got := f.manager.ActiveCount(); got != 1 {
			t.Fatalf("losing abort removed active tracking: active=%d", got)
		}
		t4aLifecycleRequireOpen(t, run.finalizationDone, "finalizationDone while normal owner is blocked")
		t4aLifecycleRequireOpen(t, run.done, "run.done while normal owner is blocked")

		wrapped.Release()
		t4aLifecycleWaitClosed(t, run.done, "run lifecycle after normal Cleanup")
		if got := f.manager.ActiveCount(); got != 0 {
			t.Fatalf("active leaked after finalization: %d", got)
		}
		if _, finalized := t4aLifecycleFinalizing(t, run); !finalized {
			t.Fatal("run was not marked finalized by its owner")
		}
		if _, _, _, cleanups := wrapped.Snapshot(); cleanups != 1 {
			t.Fatalf("Cleanup ran %d times, want exactly the owner's once", cleanups)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.manager.Close(ctx); err != nil {
			t.Fatalf("Close after completed lifecycle: %v", err)
		}
	})

	t.Run("external_abort_wins", func(t *testing.T) {
		f := newT4AFixture(t, "lifecycle-abort-wins")
		var wrapped *t4aBlockingCleanupRunner
		t4aInstallBlockingCleanup(f, &wrapped)
		_, run := f.startOneRun(t, "lifecycle-abort-wins")
		if wrapped == nil {
			t.Fatal("blocking cleanup runner was not installed")
		}
		defer wrapped.Release()

		abortDone := make(chan struct{})
		go func() {
			defer close(abortDone)
			f.manager.abortRun(run, "audit_external_abort")
		}()
		t4aLifecycleWaitClosed(t, wrapped.entered, "external abort Cleanup entry")

		// Wait returns and the local runRunner exits, but the external owner is
		// still inside Cleanup. The overall signal must remain open.
		f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		t4aLifecycleWaitClosed(t, run.waitDone, "Wait settlement behind blocked owner")
		t4aLifecycleRequireOpen(t, run.finalizationDone, "finalizationDone while abort owner is blocked")
		t4aLifecycleRequireOpen(t, run.done, "run.done while abort owner is blocked")
		if got := f.manager.ActiveCount(); got != 1 {
			t.Fatalf("blocked abort owner lost active tracking: active=%d", got)
		}
		finalizing, finalized := t4aLifecycleFinalizing(t, run)
		if !finalizing || finalized {
			t.Fatalf("blocked abort state: finalizing=%v finalized=%v", finalizing, finalized)
		}
		select {
		case <-abortDone:
			t.Fatal("external abort finished before its Cleanup barrier was released")
		default:
		}

		wrapped.Release()
		t4aLifecycleWaitClosed(t, abortDone, "external abort completion")
		t4aLifecycleWaitClosed(t, run.done, "run lifecycle after external abort")
		if _, _, _, cleanups := wrapped.Snapshot(); cleanups != 1 {
			t.Fatalf("Cleanup ran %d times, want exactly the winning abort's once", cleanups)
		}
		attempt := f.reloadAttempt(run.attempt)
		if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
			t.Fatalf("external abort did not retain an unknown hold: %+v", attempt)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := f.manager.Close(ctx); err != nil {
			t.Fatalf("Close after external abort lifecycle: %v", err)
		}
	})
}

// No database, runner, target or real resources are needed. Holding manager.mu
// makes publication-before-error-recording directly observable instead of
// relying on a probabilistic scheduling stress test. The same assertions are
// kept in the external review overlay.
func TestNativeCampaignLifecycleFinalizationPublishesFailureBeforeCompletion(t *testing.T) {
	m := &nativeCampaignManager{
		active: map[int64]*nativeCampaignRun{},
	}
	run := &nativeCampaignRun{
		attemptID:        991,
		done:             make(chan struct{}),
		localDone:        make(chan struct{}), // left open: no lifecycle completion
		finalizationDone: make(chan struct{}),
		cancel:           func() {},
	}
	m.active[run.attemptID] = run
	sentinel := errors.New("synthetic finalization persistence failure")
	run.recordFinalizationError(sentinel)
	if !run.beginFinalization() {
		t.Fatal("could not acquire fresh finalization ownership")
	}

	m.mu.Lock()
	locked := true
	finished := make(chan struct{})
	entered := make(chan struct{})
	defer func() {
		if locked {
			m.mu.Unlock()
		}
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("finishFinalization did not exit after the manager barrier was released")
		}
	}()
	go func() {
		defer close(finished)
		close(entered)
		m.finishFinalization(run)
	}()
	<-entered
	select {
	case <-run.finalizationDone:
		t.Fatal("finalizationDone was published while the manager could not yet record the failure")
	case <-time.After(300 * time.Millisecond):
		// Correct order blocks on manager.mu before publishing completion.
	}
	// The manager lock is still held, so the finalizer cannot have recorded its
	// failure or released active ownership.
	if _, recorded := m.finalizationFailures[run.attemptID]; recorded {
		t.Fatal("failure became visible before the manager recorded it under the lock")
	}
	if _, active := m.active[run.attemptID]; !active {
		t.Fatal("active ownership was released before the failure record was durable")
	}
	m.mu.Unlock()
	locked = false

	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("finalization failed to complete after releasing the manager barrier")
	}
	m.mu.Lock()
	recorded := m.finalizationFailures[run.attemptID]
	_, stillActive := m.active[run.attemptID]
	m.mu.Unlock()
	if !errors.Is(recorded, sentinel) {
		t.Fatalf("missing retained failure: %v", recorded)
	}
	if stillActive {
		t.Fatal("finalization owner did not release active ownership")
	}
	select {
	case <-run.finalizationDone:
	default:
		t.Fatal("completion was not published after recording the failure")
	}
	t4aLifecycleRequireOpen(t, run.done, "run.done without local completion")
}

// A cleanup error may not be reported as completed/verified; the failed final
// write still has to retain the hold.
func TestNativeCampaignLifecycleCleanupFailureKeepsHold(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-cleanup-failure")
	f.factory.hook = func(r *t4aFakeRunner) {
		r.cleanupErr = errors.New("synthetic cleanup failure")
	}
	_, run := f.startOneRun(t, "lifecycle-cleanup-failure")
	f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
	t4aLifecycleWaitClosed(t, run.done, "failed-cleanup finalization")

	attempt := f.reloadAttempt(run.attempt)
	if attempt.State != "failed" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("cleanup failure falsely completed: %+v", attempt)
	}
	if err := run.finalizationFailure(); err != nil {
		t.Fatalf("cleanup failure should not be a persistence failure: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.manager.Close(ctx); err != nil {
		t.Fatalf("Close after fail-closed cleanup: %v", err)
	}
}

// Halt failure must surface an explicit close error and keep the DB hold.
func TestNativeCampaignLifecycleHaltFailureCloseErrors(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-halt-failure")
	f.manager.leases = t4aFailingHaltLeaseStore{
		nativeCampaignLeaseStore: nativeCampaignDBLeaseStore{pg: f.pg},
	}
	_, run := f.startOneRun(t, "lifecycle-halt-failure")
	abortDone := make(chan struct{})
	go func() {
		defer close(abortDone)
		f.manager.abortRun(run, "halt_failure")
	}()
	t4aLifecycleWaitClosed(t, abortDone, "abort with failing halt")
	t4aLifecycleWaitClosed(t, run.done, "lifecycle with failing halt")

	attempt := f.reloadAttempt(run.attempt)
	if attempt.CleanupStatus == "verified" || !attempt.ResourceHold {
		t.Fatalf("failed halt falsely released/verified the hold: %+v", attempt)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := f.manager.Close(ctx)
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close err=%v want explicit persistence failure", err)
	}
}

// A Finalize DB failure falls back to the conservative interrupted/unknown hold,
// but Close must not report a clean finalization.
func TestNativeCampaignLifecycleFinalizeFailureCloseErrors(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-finalize-failure")
	campaign, run := f.startOneRun(t, "lifecycle-finalize-failure")
	if _, err := f.pg.Exec(`UPDATE native_campaign_attempts
		SET lease_expires_at=now()-interval '1 second'
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3`,
		f.task.ID, campaign.ID, run.attemptID); err != nil {
		t.Fatal(err)
	}
	f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
	t4aLifecycleWaitClosed(t, run.done, "finalize-failure lifecycle")

	attempt := f.reloadAttempt(run.attempt)
	if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("failed Finalize did not retain the hold: %+v", attempt)
	}
	if err := run.finalizationFailure(); err == nil {
		t.Fatal("failed Finalize was not recorded as a persistence failure")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := f.manager.Close(ctx)
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close err=%v want explicit Finalize failure", err)
	}
}

// Wait may finish before Cleanup, or Cleanup may finish while a non-cooperative
// Wait is still blocked. Neither order alone completes the overall lifecycle.
func TestNativeCampaignLifecycleWaitAndCleanupOrder(t *testing.T) {
	t.Run("wait_before_cleanup", func(t *testing.T) {
		f := newT4AFixture(t, "lifecycle-wait-first")
		var wrapped *t4aBlockingCleanupRunner
		t4aInstallBlockingCleanup(f, &wrapped)
		_, run := f.startOneRun(t, "lifecycle-wait-first")
		if wrapped == nil {
			t.Fatal("blocking cleanup runner was not installed")
		}
		defer wrapped.Release()

		f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
		t4aLifecycleWaitClosed(t, run.waitDone, "Wait before blocked Cleanup")
		t4aLifecycleRequireOpen(t, run.finalizationDone, "finalizationDone while Cleanup still blocked")
		t4aLifecycleRequireOpen(t, run.done, "run.done while Cleanup still blocked")
		wrapped.Release()
		t4aLifecycleWaitClosed(t, run.done, "lifecycle after releasing Cleanup")
	})

	t.Run("cleanup_before_wait", func(t *testing.T) {
		f := newT4AFixture(t, "lifecycle-cleanup-first")
		releaseWait := make(chan struct{})
		var releaseOnce sync.Once
		release := func() { releaseOnce.Do(func() { close(releaseWait) }) }
		defer release()
		f.factory.hook = func(r *t4aFakeRunner) {
			r.mu.Lock()
			r.waitBlock = releaseWait
			r.waitIgnoreCtx = true
			r.waitEntered = make(chan struct{})
			r.mu.Unlock()
		}
		_, run := f.startOneRun(t, "lifecycle-cleanup-first")
		runner := f.factory.Last()
		runner.mu.Lock()
		waitEntered := runner.waitEntered
		runner.mu.Unlock()
		t4aLifecycleWaitClosed(t, waitEntered, "non-cooperative Wait entry")

		abortDone := make(chan struct{})
		go func() {
			defer close(abortDone)
			f.manager.abortRun(run, "cleanup_first")
		}()
		t4aLifecycleWaitClosed(t, abortDone, "abort Cleanup/Halt completion")
		t4aLifecycleWaitClosed(t, run.finalizationDone, "finalization completion before Wait")
		if !run.isFinalized() {
			t.Fatal("finalizer did not mark the run finalized")
		}
		if got := f.manager.ActiveCount(); got != 0 {
			t.Fatalf("active not released by finalizer: %d", got)
		}
		t4aLifecycleRequireOpen(t, run.waitDone, "Wait after finalizer completed")
		t4aLifecycleRequireOpen(t, run.done, "run.done while Wait is still blocked")

		release()
		t4aLifecycleWaitClosed(t, run.done, "lifecycle after blocked Wait release")
		t4aLifecycleWaitClosed(t, run.transportDone, "lifecycle tracking after blocked Wait release")
	})
}

// Two concurrent Close calls must both refuse premature success while an
// external finalizer still owns a blocked Cleanup.
func TestNativeCampaignLifecycleConcurrentCloseExternalFinalizer(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-two-close")
	var wrapped *t4aBlockingCleanupRunner
	t4aInstallBlockingCleanup(f, &wrapped)
	f.manager.stopTimeout = 200 * time.Millisecond
	_, run := f.startOneRun(t, "lifecycle-two-close")
	if wrapped == nil {
		t.Fatal("blocking cleanup runner was not installed")
	}
	defer wrapped.Release()

	abortDone := make(chan struct{})
	go func() {
		defer close(abortDone)
		f.manager.abortRun(run, "two_close_external")
	}()
	t4aLifecycleWaitClosed(t, wrapped.entered, "external finalizer Cleanup entry")

	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		first <- f.manager.Close(ctx)
	}()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		second <- f.manager.Close(ctx)
	}()
	var firstErr, secondErr error
	for i := 0; i < 2; i++ {
		select {
		case err := <-first:
			firstErr = err
			first = nil
		case err := <-second:
			secondErr = err
			second = nil
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent Close calls did not settle")
		}
	}
	if !errors.Is(firstErr, ErrNativeCampaignCloseTimeout) || !errors.Is(secondErr, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("concurrent Close results first=%v second=%v want explicit timeout", firstErr, secondErr)
	}
	select {
	case <-abortDone:
		t.Fatal("external finalizer finished before its barrier was released")
	default:
	}

	wrapped.Release()
	t4aLifecycleWaitClosed(t, abortDone, "external finalizer after concurrent Close")
	t4aLifecycleWaitClosed(t, run.done, "run lifecycle after concurrent Close")
}

// A short caller deadline must bound the entire Close, not be extended by
// per-run/per-phase stop or cleanup timers.
func TestNativeCampaignCloseShortDeadlineNotExtended(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-short-deadline")
	var wrapped *t4aBlockingCleanupRunner
	t4aInstallBlockingCleanup(f, &wrapped)
	f.manager.stopTimeout = 5 * time.Second
	f.manager.cleanupTimeout = 5 * time.Second
	_, run := f.startOneRun(t, "lifecycle-short-deadline")
	if wrapped == nil {
		t.Fatal("blocking cleanup runner was not installed")
	}
	defer wrapped.Release()

	abortDone := make(chan struct{})
	go func() {
		defer close(abortDone)
		f.manager.abortRun(run, "short_deadline_external")
	}()
	t4aLifecycleWaitClosed(t, wrapped.entered, "external finalizer Cleanup entry")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := f.manager.Close(ctx)
	elapsed := time.Since(started)
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close err=%v want explicit timeout", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Close ignored the caller deadline and took %s", elapsed)
	}
	select {
	case <-abortDone:
		t.Fatal("external finalizer finished before its barrier was released")
	default:
	}

	wrapped.Release()
	t4aLifecycleWaitClosed(t, abortDone, "external finalizer after short Close")
	t4aLifecycleWaitClosed(t, run.done, "run lifecycle after short Close")
}

// Starting failures after registration must still converge through the single
// finalizer: no active/transport leak, a durable failed/interrupted row, and a
// Close that does not wait forever.
func TestNativeCampaignLifecycleStartingFailureConverges(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*t4aFixture)
	}{
		{
			name: "factory_error",
			setup: func(f *t4aFixture) {
				f.factory.err = errors.New("synthetic factory failure")
			},
		},
		{
			name: "runner_start_error",
			setup: func(f *t4aFixture) {
				f.factory.hook = func(r *t4aFakeRunner) {
					r.startErr = errors.New("synthetic runner start failure")
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newT4AFixture(t, "lifecycle-start-"+tc.name)
			tc.setup(f)
			campaign := f.queuedCampaign("lifecycle-start-" + tc.name)
			f.startManager()
			if err := f.manager.Step(context.Background()); err == nil {
				t.Fatal("Step succeeded despite a synthetic start failure")
			}
			if got := f.manager.ActiveCount(); got != 0 {
				t.Fatalf("start failure leaked active runs: %d", got)
			}
			if got := len(f.manager.snapshotTransports()); got != 0 {
				t.Fatalf("start failure leaked lifecycle tracking: %d", got)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := f.manager.Close(ctx); err != nil {
				t.Fatalf("Close after start failure: %v", err)
			}
			got := f.reloadCampaign(campaign)
			if got.State != "failed" && got.State != "interrupted" {
				t.Fatalf("start failure campaign state=%q", got.State)
			}
		})
	}
}

// t4aBarrierCompensationStore blocks Halt so Close can be tested against the
// pre-register claim -> MarkStarted -> compensation window.
type t4aBarrierCompensationStore struct {
	nativeCampaignLeaseStore
	markStartedErr error
	clearStartedAt bool
	checkErr       error
	haltErr        error
	haltEntered    chan struct{}
	haltRelease    chan struct{}
	haltOnce       sync.Once
}

func (s *t4aBarrierCompensationStore) MarkNativeCampaignAttemptStarted(ctx context.Context, cmd db.NativeCampaignAttemptStartCommand) (*db.NativeCampaignLeaseResult, error) {
	if s.markStartedErr != nil {
		return nil, s.markStartedErr
	}
	result, err := s.nativeCampaignLeaseStore.MarkNativeCampaignAttemptStarted(ctx, cmd)
	if err == nil && s.clearStartedAt && result != nil && result.Attempt != nil {
		result.Attempt.StartedAt = nil
	}
	return result, err
}

func (s *t4aBarrierCompensationStore) CheckNativeCampaignAttemptStart(ctx context.Context, id db.NativeCampaignLeaseIdentity) (*db.NativeCampaignLeaseResult, error) {
	if s.checkErr != nil {
		return nil, s.checkErr
	}
	return s.nativeCampaignLeaseStore.CheckNativeCampaignAttemptStart(ctx, id)
}

func (s *t4aBarrierCompensationStore) HaltNativeCampaignAttemptForLeaseLoss(ctx context.Context, cmd db.NativeCampaignLeaseHaltCommand) (*db.NativeCampaignLeaseResult, error) {
	if s.haltEntered != nil {
		s.haltOnce.Do(func() { close(s.haltEntered) })
	}
	if s.haltRelease != nil {
		select {
		case <-s.haltRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.haltErr != nil {
		return nil, s.haltErr
	}
	return s.nativeCampaignLeaseStore.HaltNativeCampaignAttemptForLeaseLoss(ctx, cmd)
}

func TestNativeCampaignCloseWaitsClaimCompensation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*t4aBarrierCompensationStore)
	}{
		{
			name: "mark_started_failure",
			setup: func(s *t4aBarrierCompensationStore) {
				s.markStartedErr = errors.New("synthetic mark-started failure")
			},
		},
		{
			name: "started_at_missing",
			setup: func(s *t4aBarrierCompensationStore) {
				s.clearStartedAt = true
			},
		},
		{
			name: "prestart_check_failure",
			setup: func(s *t4aBarrierCompensationStore) {
				s.checkErr = errors.New("synthetic start-permission failure")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newT4AFixture(t, "claim-comp-"+tc.name)
			store := &t4aBarrierCompensationStore{
				nativeCampaignLeaseStore: f.manager.leases,
				haltEntered:              make(chan struct{}),
				haltRelease:              make(chan struct{}),
			}
			tc.setup(store)
			f.manager.leases = store
			f.queuedCampaign("claim-comp-" + tc.name)
			f.startManager()
			stepDone := make(chan error, 1)
			var releaseOnce sync.Once
			stepRead := false
			defer func() {
				releaseOnce.Do(func() { close(store.haltRelease) })
				if !stepRead {
					select {
					case <-stepDone:
					case <-time.After(5 * time.Second):
						t.Error("Step did not settle after compensation release")
					}
				}
			}()
			go func() { stepDone <- f.manager.Step(context.Background()) }()
			t4aLifecycleWaitClosed(t, store.haltEntered, "claim compensation Halt entry")
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			err := f.manager.Close(ctx)
			cancel()
			if err == nil {
				t.Fatal("Close succeeded while pre-register compensation Halt was blocked")
			}
			releaseOnce.Do(func() { close(store.haltRelease) })
			select {
			case <-stepDone:
				stepRead = true
			case <-time.After(5 * time.Second):
				t.Fatal("Step did not settle after compensation release")
			}
			if got := f.manager.ActiveCount(); got != 0 {
				t.Fatalf("pre-register compensation leaked active runs: %d", got)
			}
		})
	}
}

func TestNativeCampaignCloseReportsCompensationHaltFailure(t *testing.T) {
	f := newT4AFixture(t, "claim-comp-failure")
	store := &t4aBarrierCompensationStore{
		nativeCampaignLeaseStore: f.manager.leases,
		markStartedErr:           errors.New("synthetic mark-started failure"),
		haltErr:                  errors.New("synthetic compensation Halt failure"),
	}
	f.manager.leases = store
	f.queuedCampaign("claim-comp-failure")
	f.startManager()
	if err := f.manager.Step(context.Background()); err == nil {
		t.Fatal("Step succeeded despite synthetic compensation failures")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := f.manager.Close(ctx)
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close err=%v want explicit compensation failure", err)
	}
}

func TestNativeCampaignLateFactoryHandoff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		factory func(*t4aFakeRunner, <-chan struct{}) (nativeCampaignRunner, error)
	}{
		{
			name: "late_success",
			factory: func(r *t4aFakeRunner, release <-chan struct{}) (nativeCampaignRunner, error) {
				<-release
				return r, nil
			},
		},
		{
			name: "late_partial_error",
			factory: func(r *t4aFakeRunner, release <-chan struct{}) (nativeCampaignRunner, error) {
				<-release
				return r, errors.New("synthetic late partial factory error")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newT4AFixture(t, "late-factory-"+tc.name)
			entered, release := make(chan struct{}), make(chan struct{})
			partial := newT4AFakeRunner()
			var enteredOnce sync.Once
			f.manager.factory = func(_ context.Context, _ nativeCampaignRunnerStart) (nativeCampaignRunner, error) {
				enteredOnce.Do(func() { close(entered) })
				return tc.factory(partial, release)
			}
			f.queuedCampaign("late-factory-" + tc.name)
			f.startManager()
			stepDone := make(chan error, 1)
			abortDone := make(chan struct{})
			var releaseOnce sync.Once
			stepRead, abortRead := false, false
			defer func() {
				releaseOnce.Do(func() { close(release) })
				partial.CloseEvents()
				partial.CloseTransport()
				if !stepRead {
					select {
					case <-stepDone:
					case <-time.After(5 * time.Second):
						t.Error("Step did not settle")
					}
				}
				if !abortRead {
					select {
					case <-abortDone:
					case <-time.After(5 * time.Second):
						t.Error("abort did not settle")
					}
				}
			}()
			go func() { stepDone <- f.manager.Step(context.Background()) }()
			t4aLifecycleWaitClosed(t, entered, "factory entry")
			runs := f.manager.snapshotRuns()
			if len(runs) != 1 {
				t.Fatalf("registered startup runs=%d want 1", len(runs))
			}
			go func() { defer close(abortDone); f.manager.abortRun(runs[0], "late_factory_abort") }()
			select {
			case <-abortDone:
				t.Fatal("abort completed before the factory published its runner")
			case <-time.After(250 * time.Millisecond):
			}
			releaseOnce.Do(func() { close(release) })
			select {
			case <-stepDone:
				stepRead = true
			case <-time.After(5 * time.Second):
				t.Fatal("Step did not settle after late factory publication")
			}
			select {
			case <-abortDone:
				abortRead = true
			case <-time.After(5 * time.Second):
				t.Fatal("abort did not settle after late factory publication")
			}
			_, started, _, cleanups := partial.Snapshot()
			if started {
				t.Fatal("late factory runner was started after abort won")
			}
			if cleanups != 1 {
				t.Fatalf("late factory Cleanup count=%d want exactly 1", cleanups)
			}
			if got := f.manager.ActiveCount(); got != 0 {
				t.Fatalf("late factory left active tracking: %d", got)
			}
		})
	}
}

func TestNativeCampaignCloseWhileFactoryLateSuccess(t *testing.T) {
	f := newT4AFixture(t, "late-factory-close")
	entered, release := make(chan struct{}), make(chan struct{})
	partial := newT4AFakeRunner()
	f.manager.factory = func(_ context.Context, _ nativeCampaignRunnerStart) (nativeCampaignRunner, error) {
		close(entered)
		<-release
		return partial, nil
	}
	f.queuedCampaign("late-factory-close")
	f.startManager()
	stepDone := make(chan error, 1)
	var releaseOnce sync.Once
	stepRead := false
	defer func() {
		releaseOnce.Do(func() { close(release) })
		partial.CloseEvents()
		partial.CloseTransport()
		if !stepRead {
			select {
			case <-stepDone:
			case <-time.After(5 * time.Second):
				t.Error("Step did not settle")
			}
		}
	}()
	go func() { stepDone <- f.manager.Step(context.Background()) }()
	t4aLifecycleWaitClosed(t, entered, "factory entry")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err := f.manager.Close(ctx)
	cancel()
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close err=%v want explicit timeout while factory is blocked", err)
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-stepDone:
		stepRead = true
	case <-time.After(5 * time.Second):
		t.Fatal("Step did not settle after late factory success")
	}
	_, started, _, cleanups := partial.Snapshot()
	if started {
		t.Fatal("late factory success was started after Close")
	}
	if cleanups != 1 {
		t.Fatalf("late factory Cleanup count=%d want exactly 1", cleanups)
	}
	if got := f.manager.ActiveCount(); got != 0 {
		t.Fatalf("late factory Close left active tracking: %d", got)
	}
}

func TestNativeCampaignLifecycleEvidenceFailureCloseErrors(t *testing.T) {
	f := newT4AFixture(t, "lifecycle-evidence-failure")
	_, run := f.startOneRun(t, "lifecycle-evidence-failure")
	f.storage.mu.Lock()
	f.storage.persistErr = errors.New("synthetic failed evidence write")
	f.storage.mu.Unlock()
	f.factory.Last().Deliver(t4aFinalFor(run, "completed", t4aVerifiedCleanup()))
	t4aLifecycleWaitClosed(t, run.done, "evidence persistence failure")
	attempt := f.reloadAttempt(run.attempt)
	if attempt.State != "interrupted" || attempt.CleanupStatus != "unknown" || !attempt.ResourceHold {
		t.Fatalf("evidence failure did not retain hold: %+v", attempt)
	}
	if run.finalizationFailure() == nil {
		t.Fatal("evidence persistence failure lost after successful halt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.manager.Close(ctx); !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close hid evidence failure: %v", err)
	}
}
