package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// T2 exercises the real PostgreSQL schema and the safe model helpers. It does
// not start a runner, Docker, AFL or any Campaign state machine.

func nativeCampaignHash(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func nativeCampaignJSONHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newNativeCampaignTask(t *testing.T, d *DB, label string) (*Task, *ReverseArtifact) {
	t.Helper()
	task, err := d.CreateTaskWithOptions(label, "owned campaign fixture", TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`UPDATE native_campaign_attempts
			SET state='failed', cleanup_status='verified', resource_hold=false, hold_reason=NULL
			WHERE task_id=$1 AND resource_hold`, task.ID)
		_ = d.DeleteTask(task.ID)
	})
	artifact, err := d.AddReverseArtifact(task.ID, ReverseArtifact{
		Name: "fixture.elf", Format: "elf",
		Path:      fmt.Sprintf("tasks/%d/reverse/artifacts/fixture.elf", task.ID),
		SizeBytes: 64, SHA256: nativeCampaignHash(label),
	})
	if err != nil {
		t.Fatal(err)
	}
	return task, artifact
}

func newNativeCampaign(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label string) *NativeCampaign {
	t.Helper()
	spec := json.RawMessage(fmt.Sprintf(`{"engine":"afl++","fixture":%q,"argv":["-x"]}`, label))
	c, err := d.CreateNativeCampaign(context.Background(), NativeCampaignInput{
		TaskID: task.ID, ArtifactID: artifact.ID,
		Spec: spec, SpecHash: nativeCampaignJSONHash(spec),
		ArtifactSHA256: artifact.SHA256,
		ProfileID:      "lab-linux",
		ImageDigest:    "sha256:" + nativeCampaignHash("image-"+label),
		PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: 600000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newNativeCampaignRun(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, status string) (int64, int64) {
	t.Helper()
	var runtimeID int64
	if err := d.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status)
		VALUES($1,$2,NULL,'campaign-test',$3) RETURNING id`, task.ID, artifact.ID, status).Scan(&runtimeID); err != nil {
		t.Fatal(err)
	}
	var nativeID int64
	if err := d.QueryRow(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation)
		VALUES($1,$2,$3,0,1,'campaign','running','{}') RETURNING run_id`, runtimeID, task.ID, artifact.ID).Scan(&nativeID); err != nil {
		t.Fatal(err)
	}
	if nativeID != runtimeID {
		t.Fatalf("native run id %d != runtime id %d", nativeID, runtimeID)
	}
	return runtimeID, nativeID
}

func newNativeCampaignAttempt(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, nativeID int64, attemptNo int) *NativeCampaignAttempt {
	t.Helper()
	a, err := d.CreateNativeCampaignAttempt(context.Background(), NativeCampaignAttemptInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptNo: attemptNo,
		NativeRunID: nativeID, RuntimeRunID: nativeID,
		LeaseInstance:    fmt.Sprintf("instance-%d-%d", campaign.ID, attemptNo),
		LeaseExpiresAt:   time.Now().Add(time.Minute),
		ReservedBudgetMS: 60000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func newNativeCampaignObject(t *testing.T, d *DB, task *Task, label string, length int64) *NativeCampaignObject {
	t.Helper()
	o, err := d.CreateNativeCampaignObject(context.Background(), NativeCampaignObjectInput{
		TaskID: task.ID, SHA256: nativeCampaignHash(label), Length: length,
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func newNativeCampaignManifest(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, attempt *NativeCampaignAttempt, object *NativeCampaignObject, label string) *NativeCampaignCorpusManifest {
	t.Helper()
	manifestHash := nativeCampaignHash("manifest-" + label)
	m, err := d.CreateNativeCampaignManifest(context.Background(), NativeCampaignManifestInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		ManifestSHA256: manifestHash, EntryCount: 1, TotalBytes: object.Length,
		Entries: []NativeCampaignEntryInput{{
			Ordinal: 0, ObjectID: object.ID, SHA256: object.SHA256,
			Length: object.Length, SourceType: "seed", SourceRef: "seed.bin",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func newNativeCampaignCheckpoint(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, attempt *NativeCampaignAttempt, manifest *NativeCampaignCorpusManifest) *NativeCampaignCheckpoint {
	t.Helper()
	c, err := d.CreateNativeCampaignCheckpoint(context.Background(), NativeCampaignCheckpointInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		ManifestID: manifest.ID, EntryCount: manifest.EntryCount,
		TotalBytes: manifest.TotalBytes, Truncated: manifest.Truncated,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.State != "staging" || c.VerifiedAt != nil {
		t.Fatalf("new checkpoint state=%q verified_at=%v, want staging/nil", c.State, c.VerifiedAt)
	}
	return c
}

func verifyNativeCampaignCheckpoint(t *testing.T, d *DB, checkpoint *NativeCampaignCheckpoint) {
	t.Helper()
	res, err := d.Exec(`UPDATE native_campaign_checkpoints
		SET state='verified', verified_at=now() WHERE task_id=$1 AND id=$2 AND state='staging'`,
		checkpoint.TaskID, checkpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("checkpoint verification affected %d rows", n)
	}
}

func releaseNativeCampaignAttempt(t *testing.T, d *DB, attempt *NativeCampaignAttempt, state, cleanup string) {
	t.Helper()
	hold := cleanup != "verified" && cleanup != "not_required"
	var reason any
	if hold {
		if cleanup == "pending" {
			reason = "pending"
		} else {
			reason = "cleanup_" + cleanup
		}
	}
	if _, err := d.Exec(`UPDATE native_campaign_attempts
		SET state=$3, cleanup_status=$4, resource_hold=$5, hold_reason=$6
		WHERE task_id=$1 AND id=$2`,
		attempt.TaskID, attempt.ID, state, cleanup, hold, reason); err != nil {
		t.Fatal(err)
	}
}

func mustNativeCampaignSQLFail(t *testing.T, d *DB, query string, args ...any) {
	t.Helper()
	if _, err := d.Exec(query, args...); err == nil {
		t.Fatalf("statement unexpectedly succeeded: %s", query)
	}
}

func createScratchDatabase(t *testing.T, d *DB, dsn, prefix string) string {
	t.Helper()
	name := fmt.Sprintf("%s_%d_test", prefix, time.Now().UnixNano())
	if _, err := d.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DROP DATABASE IF EXISTS "` + name + `" WITH (FORCE)`)
	})
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, name)
}

func wslGitdirPath(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "gitdir:"))
	if len(raw) >= 3 && raw[1] == ':' && (raw[2] == '/' || raw[2] == '\\') {
		return "/mnt/" + strings.ToLower(raw[:1]) + strings.ReplaceAll(raw[2:], "\\", "/")
	}
	return raw
}

func loadLegacySchema(t *testing.T) []byte {
	t.Helper()
	if path := os.Getenv("ARTEX_NATIVE_CAMPAIGN_OLD_SCHEMA"); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", root, "show", "755f0dd:db/schema.sql").Output()
	if err == nil {
		return out
	}
	// This workspace is a git worktree created on Windows. WSL git cannot resolve
	// the Windows "gitdir: E:/..." path on its own, so resolve it explicitly.
	if raw, readErr := os.ReadFile(filepath.Join(root, ".git")); readErr == nil {
		gitdir := wslGitdirPath(string(raw))
		out, err = exec.Command("git", "--git-dir="+gitdir, "show", "755f0dd:db/schema.sql").Output()
		if err == nil {
			return out
		}
	}
	t.Fatalf("load 755f0dd schema (set ARTEX_NATIVE_CAMPAIGN_OLD_SCHEMA): %v", err)
	return nil
}

func TestNativeCampaignSchemaInventory(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, table := range []string{
		"native_campaigns", "native_campaign_attempts", "native_campaign_objects",
		"native_campaign_corpus_manifests", "native_campaign_corpus_entries",
		"native_campaign_checkpoints", "native_campaign_evidence",
		"native_campaign_requests", "native_campaign_events",
	} {
		var got *string
		if err = d.QueryRow(`SELECT to_regclass('public.'||$1)::text`, table).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatalf("table %s is missing", table)
		}
	}
	var seq *string
	if err = d.QueryRow(`SELECT to_regclass('public.native_campaign_fence_seq')::text`).Scan(&seq); err != nil || seq == nil {
		t.Fatalf("fence sequence missing: %v %v", seq, err)
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN
		('uq_native_campaign_active_attempt','uq_native_campaign_resource_slot',
		 'native_campaign_attempts_campaign_idx','native_campaign_checkpoints_campaign_idx')`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("campaign indexes count=%d err=%v", count, err)
	}
	var modeDef, statusDef string
	if err = d.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='reverse_native_runs'::regclass AND conname='reverse_native_runs_mode_check'`).Scan(&modeDef); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(modeDef, "'campaign'") || !strings.Contains(modeDef, "'fuzz'") {
		t.Fatalf("mode constraint missing campaign/fuzz: %s", modeDef)
	}
	if err = d.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='reverse_runtime_runs'::regclass AND conname='reverse_runtime_runs_status_check'`).Scan(&statusDef); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"'paused'", "'interrupted'", "'cancelled'"} {
		if !strings.Contains(statusDef, want) {
			t.Fatalf("runtime status constraint missing %s: %s", want, statusDef)
		}
	}
}

func TestNativeCampaignRoundTripAndTaskScope(t *testing.T) {
	ctx := context.Background()
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "roundtrip")
	campaign := newNativeCampaign(t, d, task, artifact, "roundtrip")
	read, err := d.NativeCampaign(ctx, task.ID, campaign.ID)
	if err != nil {
		t.Fatal(err)
	}
	if read.SpecHash != campaign.SpecHash || read.ArtifactSHA256 != artifact.SHA256 ||
		read.ProfileID != "lab-linux" || read.State != "draft" || read.TotalBudgetMS != 600000 {
		t.Fatalf("campaign roundtrip mismatch: %+v", read)
	}
	runtimeID, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
	attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
	if attempt.NativeRunID != runtimeID || attempt.RuntimeRunID != runtimeID ||
		attempt.WorkerSlot != NativeCampaignWorkerSlot || !attempt.ResourceHold || attempt.State != "claimed" {
		t.Fatalf("attempt roundtrip mismatch: %+v", attempt)
	}
	object := newNativeCampaignObject(t, d, task, "object-roundtrip", 8)
	manifest := newNativeCampaignManifest(t, d, task, campaign, attempt, object, "roundtrip")
	entries, err := d.NativeCampaignEntries(ctx, task.ID, manifest.ID)
	if err != nil || len(entries) != 1 || entries[0].ObjectID != object.ID ||
		entries[0].SHA256 != object.SHA256 || entries[0].StorageKey != object.StorageKey {
		t.Fatalf("entries roundtrip=%+v err=%v", entries, err)
	}
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_corpus_entries SET length=9 WHERE id=$1`, entries[0].ID)
	mustNativeCampaignSQLFail(t, d, `DELETE FROM native_campaign_corpus_entries WHERE id=$1`, entries[0].ID)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_checkpoints(
		task_id,campaign_id,attempt_id,manifest_id,entry_count,total_bytes)
		VALUES($1,$2,$3,$4,2,$5)`,
		task.ID, campaign.ID, attempt.ID, manifest.ID, manifest.TotalBytes)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_corpus_manifests(
		task_id,campaign_id,attempt_id,manifest_sha256,entry_count,total_bytes)
		VALUES($1,$2,$3,$4,1,8)`,
		task.ID, campaign.ID, attempt.ID, nativeCampaignHash("manifest-without-entries"))
	checkpoint := newNativeCampaignCheckpoint(t, d, task, campaign, attempt, manifest)
	evidence, err := d.CreateNativeCampaignEvidence(ctx, NativeCampaignEvidenceInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/evidence/final.json", task.ID),
		SHA256: nativeCampaignHash("evidence"), Observation: json.RawMessage(`{"candidate_only":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	event, err := d.CreateNativeCampaignEvent(ctx, NativeCampaignEventInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: &attempt.ID,
		Kind: "campaign.created", Payload: json.RawMessage(`{"spec_hash":"x"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := d.CreateNativeCampaignRequest(ctx, NativeCampaignRequestInput{
		TaskID: task.ID, CampaignID: &campaign.ID, RequestID: "req-1",
		Action: "create", RequestHash: nativeCampaignHash("request"),
		ResponseStatus: 201, ResponseBody: json.RawMessage(`{"campaign_id":1}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Authority != "candidate-only" || event.Kind != "campaign.created" || request.Action != "create" {
		t.Fatalf("evidence/event/request mismatch: %+v %+v %+v", evidence, event, request)
	}
	checkpoints, err := d.NativeCampaignCheckpoints(ctx, task.ID, campaign.ID, 10, 0)
	if err != nil || len(checkpoints) != 1 || checkpoints[0].ID != checkpoint.ID || checkpoints[0].State != "staging" {
		t.Fatalf("checkpoint list=%+v err=%v", checkpoints, err)
	}
	evs, err := d.NativeCampaignEvidenceList(ctx, task.ID, campaign.ID, 10, 0)
	if err != nil || len(evs) != 1 || evs[0].ID != evidence.ID {
		t.Fatalf("evidence list=%+v err=%v", evs, err)
	}
	events, err := d.NativeCampaignEvents(ctx, task.ID, campaign.ID, 10, 0)
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("event list=%+v err=%v", events, err)
	}
	reqs, err := d.NativeCampaignRequests(ctx, task.ID, 10, 0)
	if err != nil || len(reqs) != 1 || reqs[0].ID != request.ID {
		t.Fatalf("request list=%+v err=%v", reqs, err)
	}
	attempts, err := d.NativeCampaignAttempts(ctx, task.ID, campaign.ID, 1, 0)
	if err != nil || len(attempts) != 1 || attempts[0].ID != attempt.ID {
		t.Fatalf("attempt list=%+v err=%v", attempts, err)
	}
	// A second campaign proves cursor pagination is bounded and task scoped.
	second := newNativeCampaign(t, d, task, artifact, "roundtrip-2")
	page, err := d.NativeCampaigns(ctx, task.ID, 1, 0)
	if err != nil || len(page) != 1 || page[0].ID != second.ID {
		t.Fatalf("first page=%+v err=%v", page, err)
	}
	page, err = d.NativeCampaigns(ctx, task.ID, 1, page[0].ID)
	if err != nil || len(page) != 1 || page[0].ID != campaign.ID {
		t.Fatalf("second page=%+v err=%v", page, err)
	}
	otherTask, _ := newNativeCampaignTask(t, d, "roundtrip-other")
	if _, err = d.NativeCampaign(ctx, otherTask.ID, campaign.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cross-task campaign read err=%v, want sql.ErrNoRows", err)
	}
	if list, err := d.NativeCampaigns(ctx, otherTask.ID, 10, 0); err != nil || len(list) != 0 {
		t.Fatalf("cross-task campaign list=%+v err=%v", list, err)
	}
}

func TestNativeCampaignUnknownStateAndNumericBounds(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "bounds")
	campaign := newNativeCampaign(t, d, task, artifact, "bounds")
	_, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
	attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)

	for name, query := range map[string]string{
		"campaign state":   `UPDATE native_campaigns SET state='bogus' WHERE id=$1 AND task_id=$2`,
		"desired state":    `UPDATE native_campaigns SET desired_state='bogus' WHERE id=$1 AND task_id=$2`,
		"cleanup status":   `UPDATE native_campaigns SET cleanup_status='bogus' WHERE id=$1 AND task_id=$2`,
		"attempt state":    `UPDATE native_campaign_attempts SET state='bogus' WHERE id=$1 AND task_id=$2`,
		"attempt phase":    `UPDATE native_campaign_attempts SET phase='bogus' WHERE id=$1 AND task_id=$2`,
		"attempt cleanup":  `UPDATE native_campaign_attempts SET cleanup_status='bogus' WHERE id=$1 AND task_id=$2`,
		"campaign charge":  `UPDATE native_campaigns SET charged_budget_ms=600001 WHERE id=$1 AND task_id=$2`,
		"attempt charge":   `UPDATE native_campaign_attempts SET charged_budget_ms=60001 WHERE id=$1 AND task_id=$2`,
		"campaign version": `UPDATE native_campaigns SET state_version=0 WHERE id=$1 AND task_id=$2`,
	} {
		t.Run(name, func(t *testing.T) {
			if strings.HasPrefix(name, "attempt") {
				mustNativeCampaignSQLFail(t, d, query, attempt.ID, task.ID)
			} else {
				mustNativeCampaignSQLFail(t, d, query, campaign.ID, task.ID)
			}
		})
	}
	// Direct inserts prove the DB CHECKs, not only the Go validators.
	bigSpec := fmt.Sprintf(`{"blob":%q}`, strings.Repeat("a", 262140))
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaigns(
		task_id,artifact_id,spec,spec_hash,artifact_sha256,profile_id,image_digest,
		policy_revision,config_revision,total_budget_ms)
		VALUES($1,$2,$3::jsonb,$4,$5,'lab-linux','sha256:x',1,1,6000)`,
		task.ID, artifact.ID, bigSpec, nativeCampaignHash("big"), artifact.SHA256)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaigns(
		task_id,artifact_id,spec,spec_hash,artifact_sha256,profile_id,image_digest,
		policy_revision,config_revision,total_budget_ms)
		VALUES($1,$2,'{}'::jsonb,$3,$4,'lab-linux','sha256:x',1,1,5999)`,
		task.ID, artifact.ID, nativeCampaignHash("small"), artifact.SHA256)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_objects(task_id,sha256,length,storage_key)
		VALUES($1,$2,0,'tasks/'||$1||'/reverse/campaigns/objects/sha256/'||substr($2,1,2)||'/'||$2)`,
		task.ID, nativeCampaignHash("bad-object"))
	if _, err := d.CreateNativeCampaign(context.Background(), NativeCampaignInput{
		TaskID: task.ID, ArtifactID: artifact.ID, Spec: json.RawMessage(`[]`),
		SpecHash: nativeCampaignHash("array"), ArtifactSHA256: artifact.SHA256,
		ProfileID: "lab-linux", ImageDigest: "sha256:x", PolicyRevision: 1,
		ConfigRevision: 1, TotalBudgetMS: 6000,
	}); err == nil {
		t.Fatal("array campaign spec accepted")
	}
	if _, err := d.CreateNativeCampaignAttempt(context.Background(), NativeCampaignAttemptInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptNo: 2,
		NativeRunID: nativeID, RuntimeRunID: nativeID + 1,
		LeaseInstance: "x", LeaseExpiresAt: time.Now().Add(time.Minute),
		ReservedBudgetMS: 6000,
	}); err == nil {
		t.Fatal("mismatched native/runtime run accepted")
	}
	// The application layer bounds canonical JSON bytes, not raw whitespace.
	compact := []byte(`{"x":"` + strings.Repeat("a", 262120) + `"}`)
	if _, err := normalizeNativeCampaignJSONObject(compact, NativeCampaignSpecBytes, "spec"); err != nil {
		t.Fatalf("canonical spec under limit rejected: %v", err)
	}
	padded := []byte("{ \"x\": \"" + strings.Repeat("a", 262120) + "\" }")
	if len(padded) <= 262120 {
		t.Fatal("test padding did not exceed compact bound")
	}
	if _, err := normalizeNativeCampaignJSONObject(padded, NativeCampaignSpecBytes, "spec"); err != nil {
		t.Fatalf("whitespace was incorrectly treated as logical bytes: %v", err)
	}
	over := []byte(`{"x":"` + strings.Repeat("a", 262140) + `"}`)
	if _, err := normalizeNativeCampaignJSONObject(over, NativeCampaignSpecBytes, "spec"); err == nil {
		t.Fatal("canonical spec over the limit accepted")
	}
}

func TestNativeCampaignOneActiveAndResourceHold(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "hold")
	campaign := newNativeCampaign(t, d, task, artifact, "hold")
	nativeID1 := int64(0)
	_, nativeID1 = newNativeCampaignRun(t, d, task, artifact, "running")
	first := newNativeCampaignAttempt(t, d, task, campaign, nativeID1, 1)
	secondCampaign := newNativeCampaign(t, d, task, artifact, "hold-2")
	_, nativeID2 := newNativeCampaignRun(t, d, task, artifact, "running")

	// Same campaign: another non-terminal Attempt violates the partial unique index.
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_attempts(
		task_id,campaign_id,attempt_no,native_run_id,runtime_run_id,lease_instance,
		lease_expires_at,reserved_budget_ms)
		VALUES($1,$2,2,$3,$3,'same-active',now()+interval '1 minute',6000)`,
		task.ID, campaign.ID, nativeID2)
	// Different campaign: the single persistent worker slot is already held.
	if _, err := d.CreateNativeCampaignAttempt(context.Background(), NativeCampaignAttemptInput{
		TaskID: task.ID, CampaignID: secondCampaign.ID, AttemptNo: 1,
		NativeRunID: nativeID2, RuntimeRunID: nativeID2,
		LeaseInstance: "other-campaign", LeaseExpiresAt: time.Now().Add(time.Minute),
		ReservedBudgetMS: 6000,
	}); err == nil {
		t.Fatal("second campaign claimed a held worker slot")
	}
	// Terminal state alone does not release the slot; cleanup must be confirmed.
	releaseNativeCampaignAttempt(t, d, first, "interrupted", "unknown")
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts
		SET resource_hold=false, hold_reason=NULL WHERE id=$1 AND task_id=$2`,
		first.ID, task.ID)
	releaseNativeCampaignAttempt(t, d, first, "failed", "failed")
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts
		SET resource_hold=false, hold_reason=NULL WHERE id=$1 AND task_id=$2`,
		first.ID, task.ID)
	if _, err := d.CreateNativeCampaignAttempt(context.Background(), NativeCampaignAttemptInput{
		TaskID: task.ID, CampaignID: secondCampaign.ID, AttemptNo: 1,
		NativeRunID: nativeID2, RuntimeRunID: nativeID2,
		LeaseInstance: "still-blocked", LeaseExpiresAt: time.Now().Add(time.Minute),
		ReservedBudgetMS: 6000,
	}); err == nil {
		t.Fatal("terminal+unknown/failed cleanup released the worker slot")
	}
	// Confirmed cleanup releases the slot.
	releaseNativeCampaignAttempt(t, d, first, "interrupted", "verified")
	second := newNativeCampaignAttempt(t, d, task, secondCampaign, nativeID2, 1)
	if !second.ResourceHold || second.State != "claimed" {
		t.Fatalf("replacement attempt mismatch: %+v", second)
	}
	// Active Attempt cannot drop its hold; pending cleanup cannot either.
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts
		SET resource_hold=false, hold_reason=NULL WHERE id=$1 AND task_id=$2`,
		second.ID, task.ID)
	releaseNativeCampaignAttempt(t, d, second, "interrupted", "pending")
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts
		SET resource_hold=false, hold_reason=NULL WHERE id=$1 AND task_id=$2`,
		second.ID, task.ID)
	// paused requires a verified checkpoint and verified cleanup.
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts
		SET state='paused', cleanup_status='verified', resource_hold=false, hold_reason=NULL
		WHERE id=$1 AND task_id=$2`, second.ID, task.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET state='paused'
		WHERE id=$1 AND task_id=$2`, secondCampaign.ID, task.ID)
	// The never-run queued empty pause is the one paused state without resources.
	empty := newNativeCampaign(t, d, task, artifact, "hold-empty")
	if _, err := d.Exec(`UPDATE native_campaigns
		SET state='paused', desired_state='paused', pause_origin='queued'
		WHERE id=$1 AND task_id=$2`, empty.ID, task.ID); err != nil {
		t.Fatalf("queued empty pause rejected: %v", err)
	}
	releaseNativeCampaignAttempt(t, d, second, "interrupted", "verified")
}

func TestNativeCampaignCompositeOwnership(t *testing.T) {
	ctx := context.Background()
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	taskA, artifactA := newNativeCampaignTask(t, d, "ownership-a")
	campaignA1 := newNativeCampaign(t, d, taskA, artifactA, "ownership-a1")
	_, nativeA1 := newNativeCampaignRun(t, d, taskA, artifactA, "running")
	attemptA1 := newNativeCampaignAttempt(t, d, taskA, campaignA1, nativeA1, 1)
	objectA1 := newNativeCampaignObject(t, d, taskA, "ownership-object-a1", 8)
	manifestA1 := newNativeCampaignManifest(t, d, taskA, campaignA1, attemptA1, objectA1, "ownership-manifest-a1")
	checkpointA1 := newNativeCampaignCheckpoint(t, d, taskA, campaignA1, attemptA1, manifestA1)
	releaseNativeCampaignAttempt(t, d, attemptA1, "interrupted", "verified")

	campaignA2 := newNativeCampaign(t, d, taskA, artifactA, "ownership-a2")
	_, nativeA2 := newNativeCampaignRun(t, d, taskA, artifactA, "running")
	attemptA2 := newNativeCampaignAttempt(t, d, taskA, campaignA2, nativeA2, 1)
	objectA2 := newNativeCampaignObject(t, d, taskA, "ownership-object-a2", 8)
	manifestA2 := newNativeCampaignManifest(t, d, taskA, campaignA2, attemptA2, objectA2, "ownership-manifest-a2")
	checkpointA2 := newNativeCampaignCheckpoint(t, d, taskA, campaignA2, attemptA2, manifestA2)
	releaseNativeCampaignAttempt(t, d, attemptA2, "interrupted", "verified")

	taskB, artifactB := newNativeCampaignTask(t, d, "ownership-b")
	campaignB := newNativeCampaign(t, d, taskB, artifactB, "ownership-b")
	_, nativeB := newNativeCampaignRun(t, d, taskB, artifactB, "running")
	attemptB := newNativeCampaignAttempt(t, d, taskB, campaignB, nativeB, 1)
	objectB := newNativeCampaignObject(t, d, taskB, "ownership-object-b", 8)
	manifestB := newNativeCampaignManifest(t, d, taskB, campaignB, attemptB, objectB, "ownership-manifest-b")
	checkpointB := newNativeCampaignCheckpoint(t, d, taskB, campaignB, attemptB, manifestB)

	// Cross-task campaign/artifact/hash binding.
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaigns(
		task_id,artifact_id,spec,spec_hash,artifact_sha256,profile_id,image_digest,
		policy_revision,config_revision,total_budget_ms)
		VALUES($1,$2,'{}'::jsonb,$3,$4,'lab-linux','sha256:x',1,1,6000)`,
		taskA.ID, artifactB.ID, nativeCampaignHash("cross-artifact"), artifactB.SHA256)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaigns(
		task_id,artifact_id,spec,spec_hash,artifact_sha256,profile_id,image_digest,
		policy_revision,config_revision,total_budget_ms)
		VALUES($1,$2,'{}'::jsonb,$3,$4,'lab-linux','sha256:x',1,1,6000)`,
		taskA.ID, artifactA.ID, nativeCampaignHash("bad-artifact-hash"), strings.Repeat("b", 64))
	// Attempt must use the same actual native/runtime run and the campaign task.
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_attempts(
		task_id,campaign_id,attempt_no,native_run_id,runtime_run_id,lease_instance,
		lease_expires_at,reserved_budget_ms)
		VALUES($1,$2,2,$3,$3,'cross-task-run',now()+interval '1 minute',6000)`,
		taskA.ID, campaignA1.ID, nativeB)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_attempts(
		task_id,campaign_id,attempt_no,native_run_id,runtime_run_id,lease_instance,
		lease_expires_at,reserved_budget_ms)
		VALUES($1,$2,2,$3,$3,'cross-campaign-task',now()+interval '1 minute',6000)`,
		taskB.ID, campaignA1.ID, nativeB)
	// Manifest and checkpoint must belong to the same campaign attempt/task.
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_corpus_manifests(
		task_id,campaign_id,attempt_id,manifest_sha256,entry_count,total_bytes)
		VALUES($1,$2,$3,$4,1,8)`,
		taskA.ID, campaignA2.ID, attemptA1.ID, nativeCampaignHash("cross-manifest"))
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_checkpoints(
		task_id,campaign_id,attempt_id,manifest_id,entry_count,total_bytes)
		VALUES($1,$2,$3,$4,1,8)`,
		taskA.ID, campaignA1.ID, attemptA1.ID, manifestA2.ID)
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_evidence(
		task_id,campaign_id,attempt_id,kind,result_path,sha256,observation)
		VALUES($1,$2,$3,'attempt_final','tasks/1/reverse/campaigns/e.json',$4,'{}'::jsonb)`,
		taskA.ID, campaignA2.ID, attemptA1.ID, nativeCampaignHash("cross-evidence"))
	// Entry snapshot must match the object's task/hash/length/storage key.
	mustNativeCampaignSQLFail(t, d, `INSERT INTO native_campaign_corpus_entries(
		task_id,manifest_id,ordinal,object_id,sha256,length,storage_key,source_type,source_ref)
		VALUES($1,$2,1,$3,$4,$5,$6,'seed','cross')`,
		taskA.ID, manifestA1.ID, objectB.ID, objectB.SHA256, objectB.Length, objectB.StorageKey)
	// Pointers cannot cross campaigns of the same task.
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET current_attempt_id=$2
		WHERE id=$1`, campaignA1.ID, attemptA2.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET latest_checkpoint_id=$2
		WHERE id=$1`, campaignA1.ID, checkpointA2.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts SET checkpoint_id=$2
		WHERE id=$1`, attemptA1.ID, checkpointA2.ID)
	// The same-task cross-campaign check via the public model still works.
	if _, err := d.CreateNativeCampaignAttempt(ctx, NativeCampaignAttemptInput{
		TaskID: taskB.ID, CampaignID: campaignA1.ID, AttemptNo: 3,
		NativeRunID: nativeB, RuntimeRunID: nativeB,
		LeaseInstance: "cross-model", LeaseExpiresAt: time.Now().Add(time.Minute),
		ReservedBudgetMS: 6000,
	}); err == nil {
		t.Fatal("model accepted a cross-task campaign attempt")
	}
	_ = checkpointA1
	_ = checkpointB
}

func TestNativeCampaignChargeAndCheckpointImmutability(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "charge")
	campaign := newNativeCampaign(t, d, task, artifact, "charge")
	_, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
	attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
	object := newNativeCampaignObject(t, d, task, "charge-object", 8)
	manifest := newNativeCampaignManifest(t, d, task, campaign, attempt, object, "charge")
	checkpoint := newNativeCampaignCheckpoint(t, d, task, campaign, attempt, manifest)

	if _, err := d.Exec(`UPDATE native_campaigns SET charged_budget_ms=1000 WHERE id=$1`, campaign.ID); err != nil {
		t.Fatal(err)
	}
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET charged_budget_ms=999 WHERE id=$1`, campaign.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET charged_budget_ms=600001 WHERE id=$1`, campaign.ID)
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET charged_budget_ms=1000 WHERE id=$1`, attempt.ID); err != nil {
		t.Fatal(err)
	}
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts SET charged_budget_ms=999 WHERE id=$1`, attempt.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts SET charged_budget_ms=60001 WHERE id=$1`, attempt.ID)

	// Immutable content-addressed objects/manifests.
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_objects SET length=9 WHERE id=$1`, object.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_corpus_manifests SET entry_count=2 WHERE id=$1`, manifest.ID)
	mustNativeCampaignSQLFail(t, d, `DELETE FROM native_campaign_objects WHERE id=$1`, object.ID)
	mustNativeCampaignSQLFail(t, d, `DELETE FROM native_campaign_corpus_manifests WHERE id=$1`, manifest.ID)

	// verified_at is required exactly when the checkpoint is verified.
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_checkpoints SET state='verified' WHERE id=$1`, checkpoint.ID)
	// A verified checkpoint is immutable and cannot be cleared from pointers.
	verifyNativeCampaignCheckpoint(t, d, checkpoint)
	if _, err := d.Exec(`UPDATE native_campaign_attempts
		SET checkpoint_id=$2, state='paused', cleanup_status='verified', resource_hold=false, hold_reason=NULL
		WHERE id=$1`, attempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`UPDATE native_campaigns
		SET state='paused', current_attempt_id=$2, latest_checkpoint_id=$3,
		    cleanup_status='verified', pause_origin='running'
		WHERE id=$1`, campaign.ID, attempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_attempts SET checkpoint_id=NULL WHERE id=$1`, attempt.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaigns SET latest_checkpoint_id=NULL WHERE id=$1`, campaign.ID)
	mustNativeCampaignSQLFail(t, d, `UPDATE native_campaign_checkpoints SET state='failed' WHERE id=$1`, checkpoint.ID)
	mustNativeCampaignSQLFail(t, d, `DELETE FROM native_campaign_checkpoints WHERE id=$1`, checkpoint.ID)
}

func TestNativeCampaignLegacyNativeRunsWindow(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "legacy-window")
	legacyIDs := make([]int64, 0, 105)
	for i := 0; i < 105; i++ {
		runtimeID, nativeID := newNativeCampaignRun(t, d, task, artifact, "completed")
		if _, err := d.Exec(`UPDATE reverse_native_runs SET mode='fuzz' WHERE run_id=$1`, nativeID); err != nil {
			t.Fatal(err)
		}
		legacyIDs = append(legacyIDs, runtimeID)
	}
	campaignIDs := make([]int64, 0, 105)
	for i := 0; i < 105; i++ {
		runtimeID, nativeID := newNativeCampaignRun(t, d, task, artifact, "completed")
		_ = nativeID
		campaignIDs = append(campaignIDs, runtimeID)
	}
	runs, err := d.NativeRuns(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 100 {
		t.Fatalf("NativeRuns rows=%d, want 100", len(runs))
	}
	if runs[0].RunID != legacyIDs[104] || runs[99].RunID != legacyIDs[5] {
		t.Fatalf("legacy window moved: %d..%d", runs[0].RunID, runs[99].RunID)
	}
	for _, run := range runs {
		if run.Mode == NativeModeCampaign {
			t.Fatalf("campaign row leaked into legacy window: %+v", run)
		}
	}
	campaignRuns, err := d.NativeCampaignRuns(task.ID, 7, 0)
	if err != nil || len(campaignRuns) != 7 {
		t.Fatalf("campaign page=%d err=%v", len(campaignRuns), err)
	}
	if campaignRuns[0].RunID != campaignIDs[104] || campaignRuns[6].RunID != campaignIDs[98] {
		t.Fatalf("campaign window mismatch: %d..%d", campaignRuns[0].RunID, campaignRuns[6].RunID)
	}
	next, err := d.NativeCampaignRuns(task.ID, 7, campaignRuns[6].RunID)
	if err != nil || len(next) != 7 || next[0].RunID != campaignIDs[97] {
		t.Fatalf("campaign cursor=%+v err=%v", next, err)
	}
	for _, run := range append(campaignRuns, next...) {
		if run.Mode != NativeModeCampaign {
			t.Fatalf("non-campaign row in campaign view: %+v", run)
		}
	}
}

func TestNativeCampaignSchemaReapplyWithRows(t *testing.T) {
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "reapply")
	pausedCampaign := newNativeCampaign(t, d, task, artifact, "reapply-paused")
	_, pausedNative := newNativeCampaignRun(t, d, task, artifact, "paused")
	pausedAttempt := newNativeCampaignAttempt(t, d, task, pausedCampaign, pausedNative, 1)
	object := newNativeCampaignObject(t, d, task, "reapply-object", 8)
	manifest := newNativeCampaignManifest(t, d, task, pausedCampaign, pausedAttempt, object, "reapply")
	checkpoint := newNativeCampaignCheckpoint(t, d, task, pausedCampaign, pausedAttempt, manifest)
	verifyNativeCampaignCheckpoint(t, d, checkpoint)
	if _, err = d.Exec(`UPDATE native_campaign_attempts
		SET state='paused', checkpoint_id=$2, cleanup_status='verified', resource_hold=false, hold_reason=NULL
		WHERE id=$1`, pausedAttempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE native_campaigns
		SET state='paused', current_attempt_id=$2, latest_checkpoint_id=$3,
		    cleanup_status='verified', pause_origin='running'
		WHERE id=$1`, pausedCampaign.ID, pausedAttempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	interruptedCampaign := newNativeCampaign(t, d, task, artifact, "reapply-interrupted")
	_, interruptedNative := newNativeCampaignRun(t, d, task, artifact, "interrupted")
	interruptedAttempt := newNativeCampaignAttempt(t, d, task, interruptedCampaign, interruptedNative, 1)
	releaseNativeCampaignAttempt(t, d, interruptedAttempt, "interrupted", "unknown")
	if _, err = d.Exec(`UPDATE native_campaigns
		SET state='interrupted', current_attempt_id=$2, cleanup_status='unknown'
		WHERE id=$1`, interruptedCampaign.ID, interruptedAttempt.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dsn)
	if err != nil {
		t.Fatalf("reapply full schema with campaign/paused/interrupted rows: %v", err)
	}
	if err = reopened.Close(); err != nil {
		t.Fatal(err)
	}
	var campaignState, cleanup, attemptState, runtimeStatus, mode string
	if err = d.QueryRow(`SELECT state,cleanup_status FROM native_campaigns WHERE id=$1 AND task_id=$2`,
		pausedCampaign.ID, task.ID).Scan(&campaignState, &cleanup); err != nil {
		t.Fatal(err)
	}
	if campaignState != "paused" || cleanup != "verified" {
		t.Fatalf("paused campaign changed: state=%s cleanup=%s", campaignState, cleanup)
	}
	if err = d.QueryRow(`SELECT state FROM native_campaign_attempts WHERE id=$1 AND task_id=$2`,
		pausedAttempt.ID, task.ID).Scan(&attemptState); err != nil || attemptState != "paused" {
		t.Fatalf("paused attempt changed: %s %v", attemptState, err)
	}
	if err = d.QueryRow(`SELECT status FROM reverse_runtime_runs WHERE id=$1`, interruptedNative).Scan(&runtimeStatus); err != nil || runtimeStatus != "interrupted" {
		t.Fatalf("interrupted runtime changed: %s %v", runtimeStatus, err)
	}
	if err = d.QueryRow(`SELECT mode FROM reverse_native_runs WHERE run_id=$1`, interruptedNative).Scan(&mode); err != nil || mode != "campaign" {
		t.Fatalf("campaign ledger mode changed: %s %v", mode, err)
	}
}

func TestNativeCampaignLegacySchemaMigration(t *testing.T) {
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	legacyDSN := createScratchDatabase(t, d, dsn, "artex_campaign_t2_legacy")
	legacy, err := sql.Open("pgx", legacyDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	oldSchema := loadLegacySchema(t)
	if _, err = legacy.Exec(string(oldSchema)); err != nil {
		t.Fatalf("apply 755f0dd schema: %v", err)
	}
	var taskID, artifactID, runtimeID int64
	if err = legacy.QueryRow(`WITH e AS (INSERT INTO explorations(description,goal)
		VALUES('legacy','legacy') RETURNING id)
		INSERT INTO tasks(name,description,goal,exploration_id,kind)
		SELECT 'legacy','legacy','legacy',id,'reverse' FROM e RETURNING id`).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	if err = legacy.QueryRow(`INSERT INTO reverse_artifacts(task_id,name,format,size_bytes,sha256,path)
		VALUES($1,'legacy.elf','elf',8,$2,'tasks/1/reverse/artifacts/legacy.elf') RETURNING id`,
		taskID, nativeCampaignHash("legacy-artifact")).Scan(&artifactID); err != nil {
		t.Fatal(err)
	}
	if err = legacy.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status)
		VALUES($1,$2,NULL,'legacy','completed') RETURNING id`, taskID, artifactID).Scan(&runtimeID); err != nil {
		t.Fatal(err)
	}
	if _, err = legacy.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation)
		VALUES($1,$2,$3,0,1,'fuzz','completed','{}')`, runtimeID, taskID, artifactID); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	migrated, err := Open(legacyDSN)
	if err != nil {
		t.Fatalf("upgrade 755f0dd schema: %v", err)
	}
	var legacyMode string
	if err = migrated.QueryRow(`SELECT mode FROM reverse_native_runs WHERE run_id=$1`, runtimeID).Scan(&legacyMode); err != nil || legacyMode != "fuzz" {
		t.Fatalf("legacy fuzz row changed: %s %v", legacyMode, err)
	}
	for _, table := range []string{"native_campaigns", "native_campaign_attempts", "native_campaign_events"} {
		var got *string
		if err = migrated.QueryRow(`SELECT to_regclass('public.'||$1)::text`, table).Scan(&got); err != nil || got == nil {
			t.Fatalf("upgrade missing table %s: %v", table, err)
		}
	}
	// New paused/interrupted runtime states and campaign ledger mode work after
	// the in-place constraint upgrade.
	var pausedRuntime, interruptedRuntime int64
	if err = migrated.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status)
		VALUES($1,$2,NULL,'legacy','paused') RETURNING id`, taskID, artifactID).Scan(&pausedRuntime); err != nil {
		t.Fatalf("paused runtime status rejected: %v", err)
	}
	if err = migrated.QueryRow(`INSERT INTO reverse_runtime_runs(task_id,artifact_id,intent_id,profile_id,status)
		VALUES($1,$2,NULL,'legacy','interrupted') RETURNING id`, taskID, artifactID).Scan(&interruptedRuntime); err != nil {
		t.Fatalf("interrupted runtime status rejected: %v", err)
	}
	for _, id := range []int64{pausedRuntime, interruptedRuntime} {
		if _, err = migrated.Exec(`INSERT INTO reverse_native_runs(run_id,task_id,artifact_id,intent_id,config_revision,mode,target_state,observation)
			VALUES($1,$2,$3,0,1,'campaign','running','{}')`, id, taskID, artifactID); err != nil {
			t.Fatalf("campaign mode rejected after upgrade: %v", err)
		}
	}
	if _, err = migrated.CreateNativeCampaign(context.Background(), NativeCampaignInput{
		TaskID: taskID, ArtifactID: artifactID, Spec: json.RawMessage(`{"engine":"afl++"}`),
		SpecHash: nativeCampaignHash("legacy-spec"), ArtifactSHA256: nativeCampaignHash("legacy-artifact"),
		ProfileID: "legacy", ImageDigest: "sha256:legacy", PolicyRevision: 1,
		ConfigRevision: 1, TotalBudgetMS: 6000,
	}); err != nil {
		t.Fatalf("create campaign on upgraded DB: %v", err)
	}
	_ = migrated.Close()
}

func TestNativeCampaignSchemaFailureRollsBack(t *testing.T) {
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scratchDSN := createScratchDatabase(t, d, dsn, "artex_campaign_t2_atomic")
	scratch, err := sql.Open("pgx", scratchDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	if _, err = scratch.Exec(schemaSQL + "\nSELECT 1/0;"); err == nil {
		t.Fatal("schema with injected failure unexpectedly succeeded")
	}
	var tasksTable, campaignTable *string
	if err = scratch.QueryRow(`SELECT to_regclass('public.tasks')::text`).Scan(&tasksTable); err != nil {
		t.Fatal(err)
	}
	if err = scratch.QueryRow(`SELECT to_regclass('public.native_campaigns')::text`).Scan(&campaignTable); err != nil {
		t.Fatal(err)
	}
	if tasksTable != nil || campaignTable != nil {
		t.Fatalf("failed schema left partial DDL: tasks=%v campaign=%v", tasksTable, campaignTable)
	}
}

func TestNativeCampaignTaskDelete(t *testing.T) {
	ctx := context.Background()
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "delete")
	campaign := newNativeCampaign(t, d, task, artifact, "delete")
	_, nativeID := newNativeCampaignRun(t, d, task, artifact, "paused")
	attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
	object := newNativeCampaignObject(t, d, task, "delete-object", 8)
	manifest := newNativeCampaignManifest(t, d, task, campaign, attempt, object, "delete")
	checkpoint := newNativeCampaignCheckpoint(t, d, task, campaign, attempt, manifest)
	verifyNativeCampaignCheckpoint(t, d, checkpoint)
	if _, err = d.Exec(`UPDATE native_campaign_attempts
		SET state='paused', checkpoint_id=$2, cleanup_status='verified', resource_hold=false, hold_reason=NULL
		WHERE id=$1`, attempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`UPDATE native_campaigns
		SET state='paused', current_attempt_id=$2, latest_checkpoint_id=$3,
		    cleanup_status='verified', pause_origin='running'
		WHERE id=$1`, campaign.ID, attempt.ID, checkpoint.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateNativeCampaignEvidence(ctx, NativeCampaignEvidenceInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/evidence/final.json", task.ID),
		SHA256: nativeCampaignHash("delete-evidence"), Observation: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateNativeCampaignEvent(ctx, NativeCampaignEventInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: &attempt.ID,
		Kind: "campaign.created", Payload: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if err = d.DeleteTask(task.ID); err != nil {
		t.Fatalf("DeleteTask with confirmed-clean campaign records: %v", err)
	}
	for _, table := range []string{
		"native_campaigns", "native_campaign_attempts", "native_campaign_objects",
		"native_campaign_corpus_manifests", "native_campaign_corpus_entries",
		"native_campaign_checkpoints", "native_campaign_evidence", "native_campaign_events",
	} {
		var count int
		if err = d.QueryRow(`SELECT count(*) FROM `+table+` WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s rows=%d err=%v after DeleteTask", table, count, err)
		}
	}

	// A resource-holding Campaign cannot silently disappear with the task.
	holdingTask, holdingArtifact := newNativeCampaignTask(t, d, "delete-holding")
	holdingCampaign := newNativeCampaign(t, d, holdingTask, holdingArtifact, "delete-holding")
	_, holdingNative := newNativeCampaignRun(t, d, holdingTask, holdingArtifact, "running")
	holdingAttempt := newNativeCampaignAttempt(t, d, holdingTask, holdingCampaign, holdingNative, 1)
	if err = d.DeleteTask(holdingTask.ID); err == nil ||
		!strings.Contains(err.Error(), "holding resources") {
		t.Fatalf("DeleteTask with resource hold err=%v, want holding-resources rejection", err)
	}
	releaseNativeCampaignAttempt(t, d, holdingAttempt, "interrupted", "verified")
	if err = d.DeleteTask(holdingTask.ID); err != nil {
		t.Fatalf("DeleteTask after confirmed cleanup: %v", err)
	}
}

func TestNativeCampaignHeldAttemptDeleteGuard(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	// Mirror the independent reviewer: claimed Attempt, resource_hold=true and no
	// checkpoint/evidence/current pointer. Every direct and indirect delete path
	// must fail before SET CONSTRAINTS can defer the ownership FKs.
	for _, table := range []string{
		"native_campaign_attempts", "native_campaigns",
		"reverse_runtime_runs", "reverse_native_runs", "tasks",
	} {
		t.Run("held-"+table, func(t *testing.T) {
			task, artifact := newNativeCampaignTask(t, d, "held-delete-"+table)
			campaign := newNativeCampaign(t, d, task, artifact, "held-delete")
			runtimeID, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
			attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
			var query string
			var id int64
			switch table {
			case "native_campaign_attempts":
				query, id = `DELETE FROM native_campaign_attempts WHERE id=$1`, attempt.ID
			case "native_campaigns":
				query, id = `DELETE FROM native_campaigns WHERE id=$1`, campaign.ID
			case "reverse_runtime_runs":
				query, id = `DELETE FROM reverse_runtime_runs WHERE id=$1`, runtimeID
			case "reverse_native_runs":
				query, id = `DELETE FROM reverse_native_runs WHERE run_id=$1`, nativeID
			case "tasks":
				query, id = `DELETE FROM tasks WHERE id=$1`, task.ID
			}
			tx, err := d.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			_, err = tx.Exec(query, id)
			if err == nil {
				_, err = tx.Exec(`SET CONSTRAINTS ALL IMMEDIATE`)
			}
			if err == nil {
				t.Fatalf("resource_hold=true row was deleted via %s", table)
			}
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
		})
	}

	// Once cleanup is verified and resource_hold=false, direct attempts,
	// Campaign cascades and the legacy whole-task delete remain legal.
	t.Run("released-direct-attempt-delete", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "released-direct-attempt")
		campaign := newNativeCampaign(t, d, task, artifact, "released-direct-attempt")
		_, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
		attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
		releaseNativeCampaignAttempt(t, d, attempt, "interrupted", "verified")
		res, err := d.Exec(`DELETE FROM native_campaign_attempts WHERE task_id=$1 AND id=$2`, task.ID, attempt.ID)
		if err != nil {
			t.Fatalf("released attempt direct delete: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("released attempt direct delete affected %d rows", n)
		}
	})
	t.Run("released-campaign-delete", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "released-campaign")
		campaign := newNativeCampaign(t, d, task, artifact, "released-campaign")
		_, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
		attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
		releaseNativeCampaignAttempt(t, d, attempt, "interrupted", "verified")
		res, err := d.Exec(`DELETE FROM native_campaigns WHERE task_id=$1 AND id=$2`, task.ID, campaign.ID)
		if err != nil {
			t.Fatalf("released campaign delete: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			t.Fatalf("released campaign delete affected %d rows", n)
		}
	})
	t.Run("released-task-delete", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "released-task")
		campaign := newNativeCampaign(t, d, task, artifact, "released-task")
		_, nativeID := newNativeCampaignRun(t, d, task, artifact, "running")
		attempt := newNativeCampaignAttempt(t, d, task, campaign, nativeID, 1)
		releaseNativeCampaignAttempt(t, d, attempt, "interrupted", "verified")
		if err := d.DeleteTask(task.ID); err != nil {
			t.Fatalf("released task delete: %v", err)
		}
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM native_campaigns WHERE task_id=$1`, task.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("campaign rows=%d err=%v after released DeleteTask", count, err)
		}
	})
}

func TestNativeCampaignSchemaFailureLeavesNoSequence(t *testing.T) {
	// The ordered reapply test lives in TestNativeCampaignSchemaReapplyWithRows.
	// This companion asserts the full schema is a single transaction: a failure
	// after the Campaign DDL must leave no new table or sequence behind.
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	scratchDSN := createScratchDatabase(t, d, dsn, "artex_campaign_t2_rollback")
	scratch, err := sql.Open("pgx", scratchDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer scratch.Close()
	if _, err = scratch.Exec(schemaSQL + "\nSELECT 1/0;"); err == nil {
		t.Fatal("injected schema failure unexpectedly succeeded")
	}
	var campaignTable, sequence *string
	if err = scratch.QueryRow(`SELECT to_regclass('public.native_campaigns')::text`).Scan(&campaignTable); err != nil {
		t.Fatal(err)
	}
	if err = scratch.QueryRow(`SELECT to_regclass('public.native_campaign_fence_seq')::text`).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if campaignTable != nil || sequence != nil {
		t.Fatalf("failed schema left campaign table/sequence: %v %v", campaignTable, sequence)
	}
}
