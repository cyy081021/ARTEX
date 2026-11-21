package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func t4cSpec(f *t4aFixture) map[string]any {
	sum := sha256.Sum256([]byte("Z"))
	return map[string]any{
		"engine": "afl++", "artifact_sha256": f.artifact.SHA256,
		"default_attempt_budget_ms": 60000,
		"argv":                      []string{"--file", "{input}"}, "input_mode": "file",
		"seeds":          []nativeCampaignSeed{{SHA256: hex.EncodeToString(sum[:]), DataBase64: "Wg=="}},
		"max_executions": 4321, "max_crashes": 7,
	}
}

func t4cCreate(t *testing.T, f *t4aFixture, fields map[string]any) *db.NativeCampaign {
	t.Helper()
	spec, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.pg.CreateNativeCampaignDraft(context.Background(), func(context.Context, db.NativeCampaignAuthorizationRequest) error { return nil }, db.NativeCampaignCreateCommand{
		TaskID: f.task.ID, RequestID: fmt.Sprintf("t4c-%d", f.seq.Add(1)), ArtifactID: f.artifact.ID,
		ProfileID: f.profile.ID, CreatorKind: "admin", Spec: spec, ArtifactSHA256: f.artifact.SHA256,
		ImageDigest: f.profile.Settings["image"].(string), PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: 600000,
	})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Campaign db.NativeCampaign `json:"campaign"`
	}
	if err := response.Decode(&body); err != nil {
		t.Fatal(err)
	}
	return &body.Campaign
}

func TestNativeCampaignManagerImmutableStartParameters(t *testing.T) {
	f := newT4AFixture(t, "t4c-parameters")
	spec := t4cSpec(f)
	// None of these untrusted extra fields may override authority or accounting.
	spec["artifact_path"] = "/untrusted"
	spec["task_id"] = 999999
	spec["attempt_budget_ms"] = 900000
	spec["execution_deadline"] = "2099-01-01T00:00:00Z"
	campaign := f.start(t4cCreate(t, f, spec), "admin", 0)
	f.startManager()
	if err := f.manager.Step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.factory.Count() != 1 {
		t.Fatalf("factory count %d", f.factory.Count())
	}
	start, started, _, _ := f.factory.Last().Snapshot()
	if !started || start.InputMode != "file" || !reflect.DeepEqual(start.Argv, []string{"--file", "{input}"}) || start.MaxExecutions != 4321 || start.MaxCrashes != 7 || !reflect.DeepEqual(start.Seeds, spec["seeds"]) {
		t.Fatalf("immutable parameters not forwarded: %+v", start)
	}
	if start.TaskID != f.task.ID || start.CampaignID != campaign.ID || start.ArtifactPath != f.artifact.Path || start.SHA256 != f.artifact.SHA256 || start.Profile.ImageID != f.imageID || start.AttemptBudgetMS != 60000 || start.ExecutionWindowMS != 55000 || start.ExecutionDeadline == spec["execution_deadline"] {
		t.Fatalf("spec overrode authority/budget: %+v", start)
	}
}

func TestNativeCampaignManagerRejectsInvalidStartParameters(t *testing.T) {
	cases := []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing_seeds", func(s map[string]any) { delete(s, "seeds") }},
		{"null_argv", func(s map[string]any) { s["argv"] = nil }},
		{"null_argument", func(s map[string]any) { s["argv"] = []any{nil, "{input}"} }},
		{"argument_type", func(s map[string]any) { s["argv"] = []any{1, "{input}"} }},
		{"argument_limit", func(s map[string]any) { s["argv"] = []string{strings.Repeat("a", 4097), "{input}"} }},
		{"raw_afl_placeholder", func(s map[string]any) { s["argv"] = []string{"@@", "{input}"} }},
		{"partial_placeholder", func(s map[string]any) { s["argv"] = []string{"--x={input}"} }},
		{"missing_file_placeholder", func(s map[string]any) { s["argv"] = []string{} }},
		{"stdin_placeholder", func(s map[string]any) { s["input_mode"] = "stdin" }},
		{"null_mode", func(s map[string]any) { s["input_mode"] = nil }},
		{"fractional_limit", func(s map[string]any) { s["max_executions"] = 100.5 }},
		{"null_limit", func(s map[string]any) { s["max_executions"] = nil }},
		{"low_limit", func(s map[string]any) { s["max_executions"] = 99 }},
		{"crash_limit", func(s map[string]any) { s["max_crashes"] = 9 }},
		{"empty_seeds", func(s map[string]any) { s["seeds"] = []nativeCampaignSeed{} }},
		{"sha_mismatch", func(s map[string]any) {
			s["seeds"] = []nativeCampaignSeed{{SHA256: strings.Repeat("a", 64), DataBase64: "Wg=="}}
		}},
		{"noncanonical_base64", func(s map[string]any) { seeds := s["seeds"].([]nativeCampaignSeed); seeds[0].DataBase64 = "Wg==\n" }},
		{"seed_count", func(s map[string]any) {
			seed := s["seeds"].([]nativeCampaignSeed)[0]
			seeds := make([]nativeCampaignSeed, 33)
			for i := range seeds {
				seeds[i] = seed
			}
			s["seeds"] = seeds
		}},
		{"seed_bytes", func(s map[string]any) {
			data := []byte(strings.Repeat("z", 4097))
			sum := sha256.Sum256(data)
			s["seeds"] = []nativeCampaignSeed{{SHA256: hex.EncodeToString(sum[:]), DataBase64: base64.StdEncoding.EncodeToString(data)}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newT4AFixture(t, "t4c-invalid-"+tc.name)
			spec := t4cSpec(f)
			tc.change(spec)
			f.start(t4cCreate(t, f, spec), "admin", 0)
			f.startManager()
			if err := f.manager.Step(context.Background()); err == nil {
				t.Fatal("invalid spec accepted")
			}
			if f.factory.Count() != 0 || f.manager.ActiveCount() != 0 {
				t.Fatal("invalid spec created a runner")
			}
		})
	}
}

// PostgreSQL JSONB already rejects U+0000 before a durable campaign can exist.
// Exercise the parser separately, without bypassing the database constraint.
func TestNativeCampaignManagerParameterParserRejectsNUL(t *testing.T) {
	spec := json.RawMessage(`{"argv":["a\u0000b","{input}"],"input_mode":"file","seeds":[{"sha256":"bbeebd879e1dff6918546dc0c179fdde505f2a21591c9a9c96e36b054ec5af83","data_base64":"Wg=="}],"max_executions":1000,"max_crashes":4}`)
	if _, err := nativeCampaignStartParameters(spec); err == nil || !strings.Contains(err.Error(), "invalid campaign argument") {
		t.Fatalf("NUL did not fail argument validation: %v", err)
	}
}

func TestNativeCampaignManagerCheckpointRestoreFailsClosed(t *testing.T) {
	f := newT4AFixture(t, "t4c-checkpoint-boundary")
	campaign, run := f.startOneRun(t, "t4c-checkpoint-boundary")
	if _, err := f.service.Pause(context.Background(), f.task.ID, campaign.ID, "pause", "t4c-pause"); err != nil {
		t.Fatal(err)
	}
	f.driveFinal(t, run.attemptID, "paused", t4aVerifiedCleanup())
	paused := f.reloadCampaign(campaign)
	if paused.LatestCheckpointID == nil || paused.CleanupStatus != "verified" {
		t.Fatalf("missing durable checkpoint: %+v", paused)
	}
	_, err := f.service.Resume(context.Background(), nativeCampaignStateCommand{
		TaskID: f.task.ID, CampaignID: paused.ID, RequestID: "t4c-resume",
		ExpectedStateVersion: paused.StateVersion, ActorKind: "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Step(context.Background()); err == nil || !strings.Contains(err.Error(), "checkpoint restore") {
		t.Fatalf("missing restore support did not fail closed: %v", err)
	}
	if f.factory.Count() != 1 {
		t.Fatal("checkpoint was silently restarted from initial seeds")
	}
	attempts, err := f.pg.NativeCampaignAttempts(context.Background(), f.task.ID, campaign.ID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 || attempts[0].AttemptNo != 2 || attempts[0].StartedAt != nil || attempts[0].ReservedBudgetMS != 60000 {
		t.Fatalf("fail-closed claim/budget boundary: %+v", attempts)
	}
}

type t4dRenewResultStore struct {
	nativeCampaignLeaseStore
	mode string
}

func (s t4dRenewResultStore) RenewNativeCampaignAttemptLease(ctx context.Context, cmd db.NativeCampaignLeaseCommand) (*db.NativeCampaignLeaseResult, error) {
	if s.mode == "db_error" {
		return nil, errors.New("injected DB renewal error")
	}
	if s.mode == "nil_result" {
		return nil, nil
	}
	result, err := s.nativeCampaignLeaseStore.RenewNativeCampaignAttemptLease(ctx, cmd)
	if err == nil && s.mode == "wrong_identity" {
		result.Attempt.FencingToken++
	}
	return result, err
}

type t4dHeartbeatRunner struct {
	*t4aFakeRunner
	fail bool
}

func (r *t4dHeartbeatRunner) Control(ctx context.Context, c nativeCampaignRunnerControl) error {
	if err := r.t4aFakeRunner.Control(ctx, c); err != nil {
		return err
	}
	if c.Action == "heartbeat" && r.fail {
		return errors.New("injected heartbeat rejection")
	}
	return nil
}
func TestNativeCampaignManagerAbsoluteLeaseHeartbeat(t *testing.T) {
	for _, mode := range []string{"success", "db_error", "nil_result", "wrong_identity", "ack_failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newT4AFixture(t, "absolute-lease-"+mode)
			_, run := f.startOneRun(t, "absolute-lease-"+mode)
			fake := f.factory.Last()
			start, _, _, _ := fake.Snapshot()
			initial, err := time.Parse(time.RFC3339Nano, start.LeaseDeadline)
			if err != nil {
				t.Fatal(err)
			}
			if initial.After(run.attempt.LeaseExpiresAt) || initial.After(run.deadline.ExecutionDeadline) {
				t.Fatal("start lease exceeds DB or execution cutoff")
			}
			f.manager.leases = t4dRenewResultStore{nativeCampaignLeaseStore: f.manager.leases, mode: mode}
			run.mu.Lock()
			run.runner = &t4dHeartbeatRunner{t4aFakeRunner: fake, fail: mode == "ack_failure"}
			run.mu.Unlock()
			err = f.manager.StepLeases(context.Background())
			_, _, controls, _ := fake.Snapshot()
			var heartbeats []nativeCampaignRunnerControl
			for _, c := range controls {
				if c.Action == "heartbeat" {
					heartbeats = append(heartbeats, c)
				}
			}
			if mode == "success" || mode == "ack_failure" {
				if len(heartbeats) != 1 {
					t.Fatalf("want one DB-authorized heartbeat, got %d (%v)", len(heartbeats), err)
				}
				attempt, e := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
				if e != nil {
					t.Fatal(e)
				}
				deadline, e := time.Parse(time.RFC3339Nano, heartbeats[0].LeaseDeadline)
				if e != nil {
					t.Fatal(e)
				}
				if deadline.After(attempt.LeaseExpiresAt) || deadline.After(run.deadline.ExecutionDeadline) {
					t.Fatal("heartbeat exceeds authority")
				}
				if mode == "success" && err != nil {
					t.Fatal(err)
				}
				if mode == "ack_failure" && err == nil {
					t.Fatal("runner rejection reported as successful renewal")
				}
			} else if len(heartbeats) != 0 || err == nil {
				t.Fatalf("invalid DB result authorized heartbeat: count=%d err=%v", len(heartbeats), err)
			}
			if mode == "nil_result" || mode == "wrong_identity" || mode == "ack_failure" {
				f.waitFor(t, "failed renewal stops runner", func() bool { return f.manager.ActiveCount() == 0 })
				attempt, e := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
				if e != nil {
					t.Fatal(e)
				}
				if attempt.State != "interrupted" || !attempt.ResourceHold || attempt.CleanupStatus != "unknown" {
					t.Fatalf("unsafe failed renewal settlement: %+v", attempt)
				}
			}
		})
	}
}

type t4dBlockedRenewStore struct {
	nativeCampaignLeaseStore
	entered, release, exited chan struct{}
}

func (s *t4dBlockedRenewStore) RenewNativeCampaignAttemptLease(ctx context.Context, _ db.NativeCampaignLeaseCommand) (*db.NativeCampaignLeaseResult, error) {
	close(s.entered)
	defer close(s.exited)
	<-s.release
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("released blocked renewal without authority")
}
func TestNativeCampaignManagerCloseDuringBlockedRenewal(t *testing.T) {
	f := newT4AFixture(t, "close-renew")
	_, run := f.startOneRun(t, "close-renew")
	blocked := &t4dBlockedRenewStore{nativeCampaignLeaseStore: f.manager.leases, entered: make(chan struct{}), release: make(chan struct{}), exited: make(chan struct{})}
	f.manager.leases = blocked
	var once sync.Once
	release := func() { once.Do(func() { close(blocked.release) }) }
	defer release()
	done := make(chan error, 1)
	go func() { done <- f.manager.StepLeases(context.Background()) }()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		t.Fatal("renewal never entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	err := f.manager.Close(ctx)
	cancel()
	if !errors.Is(err, ErrNativeCampaignCloseTimeout) {
		t.Fatalf("Close claimed success with renewal owner blocked: %v", err)
	}
	attempt, e := f.pg.NativeCampaignAttempt(context.Background(), f.task.ID, run.attemptID)
	if e != nil {
		t.Fatal(e)
	}
	if !attempt.ResourceHold {
		t.Fatal("blocked close released resource hold")
	}
	release()
	select {
	case <-blocked.exited:
	case <-time.After(time.Second):
		t.Fatal("renewal failed to exit after release")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("StepLeases remained running")
	}
	_, _, controls, _ := f.factory.Last().Snapshot()
	for _, control := range controls {
		if control.Action == "heartbeat" {
			t.Fatal("failed blocked renewal authorized heartbeat")
		}
	}
	f.waitFor(t, "close drains released renewal", func() bool { return f.manager.ActiveCount() == 0 })
}
