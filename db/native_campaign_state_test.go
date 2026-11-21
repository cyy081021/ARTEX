package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

var t3RequestSeq atomic.Int64

func t3ReqID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, t3RequestSeq.Add(1))
}

func t3AllowAuth(context.Context, NativeCampaignAuthorizationRequest) error { return nil }

func t3DenyAuth(context.Context, NativeCampaignAuthorizationRequest) error {
	return errors.New("synthetic authorization denial")
}

func t3CreateDraftWithBudget(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label string, totalBudget int64) *NativeCampaign {
	t.Helper()
	resp, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, NativeCampaignCreateCommand{
		TaskID: task.ID, RequestID: t3ReqID("create-" + label), ArtifactID: artifact.ID,
		ProfileID: "lab-linux", CreatorKind: "admin", CreatorID: 0,
		Spec:           json.RawMessage(fmt.Sprintf(`{"engine":"afl++","label":%q}`, label)),
		ArtifactSHA256: artifact.SHA256,
		ImageDigest:    "sha256:" + nativeCampaignHash("image-"+label),
		PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: totalBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Campaign NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Campaign.State != "draft" || body.Campaign.StateVersion != 1 {
		t.Fatalf("new campaign=%+v", body.Campaign)
	}
	return &body.Campaign
}

func t3CreateDraft(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label string) *NativeCampaign {
	t.Helper()
	return t3CreateDraftWithBudget(t, d, task, artifact, label, 600000)
}

func t3CreateDraftWithSpec(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label, spec string, totalBudget int64) *NativeCampaign {
	t.Helper()
	resp, err := d.CreateNativeCampaignDraft(context.Background(), t3AllowAuth, NativeCampaignCreateCommand{
		TaskID: task.ID, RequestID: t3ReqID("create-spec-" + label), ArtifactID: artifact.ID,
		ProfileID: "lab-linux", CreatorKind: "admin", CreatorID: 0,
		Spec:           json.RawMessage(spec),
		ArtifactSHA256: artifact.SHA256,
		ImageDigest:    "sha256:" + nativeCampaignHash("image-spec-"+label),
		PolicyRevision: 1, ConfigRevision: 1, TotalBudgetMS: totalBudget,
	})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Campaign NativeCampaign `json:"campaign"`
	}
	if err := resp.Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Campaign.State != "draft" || body.Campaign.StateVersion != 1 {
		t.Fatalf("new campaign=%+v", body.Campaign)
	}
	return &body.Campaign
}

func t3Start(t *testing.T, d *DB, campaign *NativeCampaign, version int64, requestID string, budget *int64) *NativeCampaign {
	t.Helper()
	if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: campaign.TaskID, CampaignID: campaign.ID, RequestID: requestID,
		ExpectedStateVersion: version, AttemptBudgetMS: budget,
	}); err != nil {
		t.Fatal(err)
	}
	return t3ReloadCampaign(t, d, campaign)
}

func t3ClaimWithCallerDefault(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, instance string, budget *int64, callerDefault int64) (*NativeCampaignClaimResult, error) {
	t.Helper()
	return d.ClaimNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignClaimCommand{
		TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: instance,
		AttemptBudgetMS: budget, DefaultAttemptBudgetMS: callerDefault,
		ProfileMaxDurationMS: 600000, PolicyMaxDurationMS: 600000,
		OperatorKind: "admin",
	})
}

func t3Claim(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, instance string, budget *int64) (*NativeCampaignClaimResult, error) {
	t.Helper()
	return t3ClaimWithCallerDefault(t, d, task, campaign, instance, budget, 60000)
}

func t3MustClaim(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, instance string) *NativeCampaignClaimResult {
	t.Helper()
	res, err := t3Claim(t, d, task, campaign, instance, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func t3ReloadCampaign(t *testing.T, d *DB, campaign *NativeCampaign) *NativeCampaign {
	t.Helper()
	got, err := d.NativeCampaign(context.Background(), campaign.TaskID, campaign.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func t3ReloadAttempt(t *testing.T, d *DB, attempt *NativeCampaignAttempt) *NativeCampaignAttempt {
	t.Helper()
	got, err := d.NativeCampaignAttempt(context.Background(), attempt.TaskID, attempt.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func t3Checkpoint(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, attempt *NativeCampaignAttempt, label string) *NativeCampaignCheckpoint {
	t.Helper()
	object := newNativeCampaignObject(t, d, task, fmt.Sprintf("obj-%s-%d", label, attempt.ID), 8)
	manifest := newNativeCampaignManifest(t, d, task, campaign, attempt, object, fmt.Sprintf("%s-%d", label, attempt.ID))
	checkpoint := newNativeCampaignCheckpoint(t, d, task, campaign, attempt, manifest)
	verifyNativeCampaignCheckpoint(t, d, checkpoint)
	reloaded, err := d.NativeCampaignCheckpoint(context.Background(), task.ID, checkpoint.ID)
	if err != nil {
		t.Fatal(err)
	}
	return reloaded
}

func t3Evidence(t *testing.T, d *DB, task *Task, campaign *NativeCampaign, attempt *NativeCampaignAttempt) *NativeCampaignEvidence {
	t.Helper()
	evidence, err := d.CreateNativeCampaignEvidence(context.Background(), NativeCampaignEvidenceInput{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: attempt.ID,
		Kind:        "attempt_final",
		ResultPath:  fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/%d.json", task.ID, campaign.ID, attempt.ID),
		SHA256:      nativeCampaignHash(fmt.Sprintf("evidence-%d-%d", campaign.ID, attempt.ID)),
		Observation: json.RawMessage(`{"format_version":1,"candidate_only":true,"findings_created":0}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func t3Finalize(cmd NativeCampaignFinalizeCommand) NativeCampaignFinalizeCommand {
	if cmd.Phase == "" {
		cmd.Phase = "finalize"
	}
	if cmd.CleanupReserveMS == 0 {
		cmd.CleanupReserveMS = 5000
	}
	return cmd
}

func t3MustFinalize(t *testing.T, d *DB, cmd NativeCampaignFinalizeCommand) *NativeCampaignFinalizeResult {
	t.Helper()
	res, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(cmd))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func t3Count(t *testing.T, d *DB, table string, taskID int64) int {
	t.Helper()
	var query string
	switch table {
	case "attempts":
		query = `SELECT count(*) FROM native_campaign_attempts WHERE task_id=$1`
	case "requests":
		query = `SELECT count(*) FROM native_campaign_requests WHERE task_id=$1`
	case "events":
		query = `SELECT count(*) FROM native_campaign_events WHERE task_id=$1`
	case "runs":
		query = `SELECT count(*) FROM reverse_native_runs WHERE task_id=$1 AND mode='campaign'`
	case "runtime":
		query = `SELECT count(*) FROM reverse_runtime_runs WHERE task_id=$1 AND profile_id='lab-linux'`
	default:
		t.Fatalf("unknown table alias %q", table)
	}
	var count int
	if err := d.QueryRow(query, taskID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func t3EventKindCount(t *testing.T, d *DB, taskID, campaignID int64, kind string) int {
	t.Helper()
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM native_campaign_events
		WHERE task_id=$1 AND campaign_id=$2 AND kind=$3`, taskID, campaignID, kind).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func t3PreparePausedCampaign(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label string) (*NativeCampaign, *NativeCampaignAttempt, *NativeCampaignCheckpoint, *NativeCampaignEvidence) {
	t.Helper()
	campaign := t3CreateDraft(t, d, task, artifact, label)
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("start-"+label), nil)
	claim := t3MustClaim(t, d, task, campaign, "inst-"+label+"-1")
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("pause-" + label),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	checkpoint := t3Checkpoint(t, d, task, campaign, claim.Attempt, label)
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "paused",
		CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
		ActualElapsedMS: 4000, CleanupElapsedMS: 1000,
	})
	return res.Campaign, res.Attempt, checkpoint, evidence
}

func t3PreparePausedCampaignWithSpec(t *testing.T, d *DB, task *Task, artifact *ReverseArtifact, label, spec string, totalBudget int64) (*NativeCampaign, *NativeCampaignAttempt) {
	t.Helper()
	campaign := t3CreateDraftWithSpec(t, d, task, artifact, label, spec, totalBudget)
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("start-spec-"+label), nil)
	claim := t3MustClaim(t, d, task, campaign, "inst-spec-"+label+"-1")
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("pause-spec-" + label),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	checkpoint := t3Checkpoint(t, d, task, campaign, claim.Attempt, label)
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "paused",
		CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
		ActualElapsedMS: 4000, CleanupElapsedMS: 1000,
	})
	return res.Campaign, res.Attempt
}

func TestNativeCampaignTransitions(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("legal_lifecycle", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "transitions-legal")
		campaign := t3CreateDraft(t, d, task, artifact, "transitions-legal")
		campaign = t3Start(t, d, campaign, 1, t3ReqID("start-legal"), nil)
		first := t3MustClaim(t, d, task, campaign, "legal-instance-1")
		campaign = t3ReloadCampaign(t, d, campaign)
		if first.Attempt.AttemptNo != 1 || campaign.State != "running" || campaign.StateVersion != 3 {
			t.Fatalf("first claim=%+v campaign=%+v", first.Attempt, campaign)
		}
		if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("pause-legal"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		checkpoint := t3Checkpoint(t, d, task, campaign, first.Attempt, "pause-legal")
		evidence := t3Evidence(t, d, task, campaign, first.Attempt)
		paused := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: first.Attempt.ID,
			FencingToken: first.Attempt.FencingToken, LeaseOwner: first.Attempt.LeaseOwner,
			LeaseInstance: first.Attempt.LeaseInstance, TargetState: "paused",
			CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
			ActualElapsedMS: 4000, CleanupElapsedMS: 1000,
		})
		campaign = paused.Campaign
		if campaign.State != "paused" || campaign.StateVersion != 5 || campaign.LatestCheckpointID == nil ||
			*campaign.LatestCheckpointID != checkpoint.ID {
			t.Fatalf("paused finalize=%+v", campaign)
		}
		charged := campaign.ChargedBudgetMS
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("resume-legal"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		if campaign.State != "queued" || campaign.ChargedBudgetMS != charged || campaign.TotalBudgetMS != 600000 {
			t.Fatalf("resume=%+v", campaign)
		}
		if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("pause-queued"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		if campaign.State != "paused" || campaign.CurrentAttemptID == nil ||
			campaign.LatestCheckpointID == nil || *campaign.LatestCheckpointID != checkpoint.ID ||
			campaign.ChargedBudgetMS != charged || campaign.CleanupStatus != "verified" {
			t.Fatalf("queued pause lost checkpoint=%+v", campaign)
		}
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("resume-2"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		second := t3MustClaim(t, d, task, campaign, "legal-instance-2")
		if second.Attempt.AttemptNo != 2 || second.Attempt.FencingToken <= first.Attempt.FencingToken {
			t.Fatalf("second claim=%+v", second.Attempt)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		evidence2 := t3Evidence(t, d, task, campaign, second.Attempt)
		completed := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: second.Attempt.ID,
			FencingToken: second.Attempt.FencingToken, LeaseOwner: second.Attempt.LeaseOwner,
			LeaseInstance: second.Attempt.LeaseInstance, TargetState: "completed",
			CleanupStatus: "verified", EvidenceID: evidence2.ID,
			ActualElapsedMS: 2000, CleanupElapsedMS: 1000,
		})
		campaign = completed.Campaign
		if campaign.State != "completed" || campaign.DesiredState != "none" || campaign.StateVersion != 10 {
			t.Fatalf("completed=%+v", campaign)
		}
		charged = campaign.ChargedBudgetMS
		events := t3Count(t, d, "events", task.ID)
		duplicate := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: second.Attempt.ID,
			FencingToken: second.Attempt.FencingToken, LeaseOwner: second.Attempt.LeaseOwner,
			LeaseInstance: second.Attempt.LeaseInstance, TargetState: "completed",
			CleanupStatus: "verified", EvidenceID: evidence2.ID,
			ActualElapsedMS: 999999, CleanupElapsedMS: 1000,
		})
		if !duplicate.AlreadyFinalized || t3ReloadCampaign(t, d, campaign).ChargedBudgetMS != charged ||
			t3Count(t, d, "events", task.ID) != events {
			t.Fatalf("duplicate final mutated state: %+v", duplicate)
		}
		for name, call := range map[string]func() error{
			"start": func() error {
				_, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("terminal-start"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
			"resume": func() error {
				_, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("terminal-resume"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
			"pause": func() error {
				_, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("terminal-pause"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
			"cancel": func() error {
				_, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("terminal-cancel"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
		} {
			if err := call(); NativeCampaignErrorCode(err) != "terminal_campaign" {
				t.Fatalf("%s terminal code=%q err=%v", name, NativeCampaignErrorCode(err), err)
			}
		}
	})

	t.Run("draft_queued_stopping_edges", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "transitions-edges")
		campaign := t3CreateDraft(t, d, task, artifact, "transitions-edges")
		if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("draft-pause"),
			ExpectedStateVersion: campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "not_started" {
			t.Fatalf("draft pause code=%q", NativeCampaignErrorCode(err))
		}
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("draft-resume"),
			ExpectedStateVersion: campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "not_started" {
			t.Fatalf("draft resume code=%q", NativeCampaignErrorCode(err))
		}
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("edges-start"), nil)
		resp, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("queued-start-again"),
			ExpectedStateVersion: campaign.StateVersion,
		})
		if err != nil || !resp.AlreadyQueued || t3ReloadCampaign(t, d, campaign).StateVersion != campaign.StateVersion {
			t.Fatalf("queued start idempotent resp=%+v err=%v", resp, err)
		}
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("queued-resume"),
			ExpectedStateVersion: campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "state_conflict" {
			t.Fatalf("queued resume code=%q", NativeCampaignErrorCode(err))
		}
		if _, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("queued-cancel"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		if campaign.State != "cancelled" || campaign.CleanupStatus != "not_required" {
			t.Fatalf("queued cancel=%+v", campaign)
		}
		for name, call := range map[string]func() error{
			"start": func() error {
				_, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("cancelled-start"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
			"cancel": func() error {
				_, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
					TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("cancelled-cancel"),
					ExpectedStateVersion: campaign.StateVersion,
				})
				return err
			},
		} {
			if err := call(); NativeCampaignErrorCode(err) != "terminal_campaign" {
				t.Fatalf("cancelled %s code=%q", name, NativeCampaignErrorCode(err))
			}
		}
	})
}

func TestNativeCampaignTransitionsQueuedPausePreservesCheckpoint(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "queued-preserve")
	campaign, attempt, checkpoint, _ := t3PreparePausedCampaign(t, d, task, artifact, "queued-preserve")
	charged := campaign.ChargedBudgetMS
	if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("preserve-resume"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("preserve-pause"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if campaign.State != "paused" || campaign.PauseOrigin != "queued" ||
		campaign.CurrentAttemptID == nil || *campaign.CurrentAttemptID != attempt.ID ||
		campaign.LatestCheckpointID == nil || *campaign.LatestCheckpointID != checkpoint.ID ||
		campaign.CleanupStatus != "verified" || campaign.ChargedBudgetMS != charged {
		t.Fatalf("queued pause lost checkpoint/charge: %+v", campaign)
	}
}

func TestNativeCampaignTransitionsEarlyPauseCheckpoint(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "early-pause")
	campaign := t3CreateDraft(t, d, task, artifact, "early-pause")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("early-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "early-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("early-pause-request"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	checkpoint := t3Checkpoint(t, d, task, campaign, claim.Attempt, "early")
	if checkpoint.EntryCount < 1 {
		t.Fatalf("early checkpoint entry_count=%d", checkpoint.EntryCount)
	}
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "paused",
		CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
		ActualElapsedMS: 500, CleanupElapsedMS: 500,
	})
	if res.Campaign.State != "paused" || res.Attempt.CheckpointID == nil || *res.Attempt.CheckpointID != checkpoint.ID {
		t.Fatalf("early pause finalize=%+v", res.Campaign)
	}
}

func TestNativeCampaignTransitionsFinalizeGate(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "finalize-gate")
	campaign := t3CreateDraft(t, d, task, artifact, "finalize-gate")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("gate-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "gate-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	checkpoint := t3Checkpoint(t, d, task, campaign, claim.Attempt, "gate")
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	cmd := NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "paused",
		CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 500,
	}
	beforeVersion := campaign.StateVersion
	beforeEvents := t3Count(t, d, "events", task.ID)
	if _, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(cmd)); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("unrequested paused code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "running" || got.StateVersion != beforeVersion {
		t.Fatalf("unrequested paused changed campaign: %+v", got)
	}
	if t3Count(t, d, "events", task.ID) != beforeEvents {
		t.Fatal("unrequested paused wrote events")
	}
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("gate-pause"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if _, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("gate-cancel"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	if campaign.State != "stopping" || campaign.DesiredState != "cancelled" {
		t.Fatalf("cancel upgrade=%+v", campaign)
	}
	beforeVersion = campaign.StateVersion
	beforeEvents = t3Count(t, d, "events", task.ID)
	if _, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(cmd)); NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("stale paused after cancel code=%q", NativeCampaignErrorCode(err))
	}
	if got := t3ReloadCampaign(t, d, campaign); got.State != "stopping" || got.DesiredState != "cancelled" ||
		got.StateVersion != beforeVersion {
		t.Fatalf("stale paused overwrote cancel: %+v", got)
	}
	if got := t3ReloadAttempt(t, d, claim.Attempt); got.State != "claimed" || got.ChargedBudgetMS != 0 {
		t.Fatalf("stale paused wrote attempt: %+v", got)
	}
	if t3Count(t, d, "events", task.ID) != beforeEvents {
		t.Fatal("stale paused wrote events")
	}
	completed := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "completed",
		CleanupStatus: "verified", EvidenceID: evidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 500,
	})
	if completed.Campaign.State != "completed" || t3EventKindCount(t, d, task.ID, campaign.ID, "cancel_lost_race") != 1 ||
		t3EventKindCount(t, d, task.ID, campaign.ID, "pause_lost_race") != 0 {
		t.Fatalf("lost race exception=%+v", completed.Campaign)
	}
}

func TestNativeCampaignTransitionsPauseLostRace(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "pause-lost-race")
	campaign := t3CreateDraft(t, d, task, artifact, "pause-lost-race")
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("plr-start"), nil)
	claim := t3MustClaim(t, d, task, campaign, "plr-instance")
	campaign = t3ReloadCampaign(t, d, campaign)
	evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("plr-pause"),
		ExpectedStateVersion: campaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	campaign = t3ReloadCampaign(t, d, campaign)
	res := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "completed",
		CleanupStatus: "verified", EvidenceID: evidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 500,
	})
	if res.Campaign.State != "completed" || t3EventKindCount(t, d, task.ID, campaign.ID, "pause_lost_race") != 1 {
		t.Fatalf("pause lost race=%+v", res.Campaign)
	}
}

func TestNativeCampaignFinalizeCleanupPendingAndNotRequired(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "cleanup-final-gate")

	pendingCampaign := t3CreateDraft(t, d, task, artifact, "cleanup-pending")
	pendingCampaign = t3Start(t, d, pendingCampaign, pendingCampaign.StateVersion, t3ReqID("pending-start"), nil)
	pendingClaim := t3MustClaim(t, d, task, pendingCampaign, "pending-instance")
	pendingCampaign = t3ReloadCampaign(t, d, pendingCampaign)
	pendingEvidence := t3Evidence(t, d, task, pendingCampaign, pendingClaim.Attempt)
	if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: task.ID, CampaignID: pendingCampaign.ID, RequestID: t3ReqID("pending-pause"),
		ExpectedStateVersion: pendingCampaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	pendingCampaign = t3ReloadCampaign(t, d, pendingCampaign)
	pending, err := d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: pendingCampaign.ID, AttemptID: pendingClaim.Attempt.ID,
		FencingToken: pendingClaim.Attempt.FencingToken, LeaseOwner: pendingClaim.Attempt.LeaseOwner,
		LeaseInstance: pendingClaim.Attempt.LeaseInstance, TargetState: "failed",
		CleanupStatus: "pending", EvidenceID: pendingEvidence.ID,
		ActualElapsedMS: 0, CleanupElapsedMS: 0,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if pending.Settlement.LedgerMS != pending.Attempt.ReservedBudgetMS ||
		pending.Attempt.ChargedBudgetMS != pending.Attempt.ReservedBudgetMS ||
		!pending.Attempt.ResourceHold {
		t.Fatalf("pending cleanup not conservative: settlement=%+v attempt=%+v", pending.Settlement, pending.Attempt)
	}
	if _, err := d.RetryNativeCampaignCleanup(context.Background(), t3AllowAuth, NativeCampaignCleanupCommand{
		TaskID: task.ID, CampaignID: pendingCampaign.ID, AttemptID: pendingClaim.Attempt.ID,
		CleanupVerified: true, CleanupElapsedMS: 1000,
	}); err != nil {
		t.Fatal(err)
	}

	nrTask, nrArtifact := newNativeCampaignTask(t, d, "cleanup-not-required-task")
	cancelCampaign := t3CreateDraft(t, d, nrTask, nrArtifact, "cleanup-not-required")
	cancelCampaign = t3Start(t, d, cancelCampaign, cancelCampaign.StateVersion, t3ReqID("nr-start"), nil)
	cancelClaim := t3MustClaim(t, d, nrTask, cancelCampaign, "nr-instance")
	cancelCampaign = t3ReloadCampaign(t, d, cancelCampaign)
	cancelEvidence := t3Evidence(t, d, nrTask, cancelCampaign, cancelClaim.Attempt)
	if _, err := d.Exec(`UPDATE native_campaign_attempts SET owned_resources='{"container":"artex-test"}'
		WHERE task_id=$1 AND campaign_id=$2 AND id=$3`,
		nrTask.ID, cancelCampaign.ID, cancelClaim.Attempt.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CancelNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: nrTask.ID, CampaignID: cancelCampaign.ID, RequestID: t3ReqID("nr-cancel"),
		ExpectedStateVersion: cancelCampaign.StateVersion,
	}); err != nil {
		t.Fatal(err)
	}
	cancelCampaign = t3ReloadCampaign(t, d, cancelCampaign)
	beforeEvents := t3Count(t, d, "events", nrTask.ID)
	beforeAttempt := t3ReloadAttempt(t, d, cancelClaim.Attempt)
	_, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, t3Finalize(NativeCampaignFinalizeCommand{
		TaskID: nrTask.ID, CampaignID: cancelCampaign.ID, AttemptID: cancelClaim.Attempt.ID,
		FencingToken: cancelClaim.Attempt.FencingToken, LeaseOwner: cancelClaim.Attempt.LeaseOwner,
		LeaseInstance: cancelClaim.Attempt.LeaseInstance, TargetState: "cancelled",
		CleanupStatus: "not_required", EvidenceID: cancelEvidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 0,
	}))
	if NativeCampaignErrorCode(err) != "state_conflict" {
		t.Fatalf("not_required with owned resources code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	if t3Count(t, d, "events", nrTask.ID) != beforeEvents {
		t.Fatal("not_required rejection wrote events")
	}
	if got := t3ReloadAttempt(t, d, cancelClaim.Attempt); got.ChargedBudgetMS != beforeAttempt.ChargedBudgetMS ||
		got.State != beforeAttempt.State || !got.ResourceHold {
		t.Fatalf("not_required rejection wrote attempt: %+v", got)
	}
}

func TestNativeCampaignClaimAuthorizedBudgetReadback(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, artifact := newNativeCampaignTask(t, d, "budget-readback")
	campaign := t3CreateDraft(t, d, task, artifact, "budget-readback")
	capValue := int64(30000)
	campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("readback-start"), &capValue)
	events, err := d.NativeCampaignEvents(context.Background(), task.ID, campaign.ID, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	var queuedPayload struct {
		AttemptBudgetMS *int64 `json:"attempt_budget_ms"`
	}
	if len(events) == 0 {
		t.Fatal("no queued event")
	}
	if err := json.Unmarshal(events[0].Payload, &queuedPayload); err != nil {
		t.Fatal(err)
	}
	if queuedPayload.AttemptBudgetMS == nil || *queuedPayload.AttemptBudgetMS != capValue {
		t.Fatalf("queued budget readback=%+v", queuedPayload)
	}
	zero, negative, below := int64(0), int64(-1), int64(5999)
	for name, budget := range map[string]*int64{"zero": &zero, "negative": &negative, "below": &below} {
		if _, err := t3Claim(t, d, task, campaign, "readback-"+name, budget); NativeCampaignErrorCode(err) != "invalid_request" {
			t.Fatalf("%s claim code=%q err=%v", name, NativeCampaignErrorCode(err), err)
		}
	}
	if t3Count(t, d, "attempts", task.ID) != 0 {
		t.Fatal("invalid explicit claims created attempts")
	}
	expand := int64(60000)
	if _, err := t3Claim(t, d, task, campaign, "readback-expand", &expand); NativeCampaignErrorCode(err) != "budget_exhausted" {
		t.Fatalf("expanded claim code=%q err=%v", NativeCampaignErrorCode(err), err)
	}
	claim := t3MustClaim(t, d, task, campaign, "readback-nil")
	if claim.Plan.ReservedBudgetMS != capValue {
		t.Fatalf("nil claim lost cap: %+v", claim.Plan)
	}

	firstEvidence := t3Evidence(t, d, task, campaign, claim.Attempt)
	t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
		TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
		FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
		LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "failed",
		CleanupStatus: "verified", EvidenceID: firstEvidence.ID,
		ActualElapsedMS: 1000, CleanupElapsedMS: 500,
	})

	resumeTask, resumeArtifact := newNativeCampaignTask(t, d, "budget-readback-resume-task")
	resumeCampaign, _, _, _ := t3PreparePausedCampaign(t, d, resumeTask, resumeArtifact, "budget-readback-resume")
	resumeCap := int64(30000)
	if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
		TaskID: resumeTask.ID, CampaignID: resumeCampaign.ID, RequestID: t3ReqID("readback-resume"),
		ExpectedStateVersion: resumeCampaign.StateVersion, AttemptBudgetMS: &resumeCap,
	}); err != nil {
		t.Fatal(err)
	}
	resumeCampaign = t3ReloadCampaign(t, d, resumeCampaign)
	events, err = d.NativeCampaignEvents(context.Background(), resumeTask.ID, resumeCampaign.ID, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	var resumePayload struct {
		AttemptBudgetMS *int64 `json:"attempt_budget_ms"`
	}
	if err := json.Unmarshal(events[0].Payload, &resumePayload); err != nil {
		t.Fatal(err)
	}
	if resumePayload.AttemptBudgetMS == nil || *resumePayload.AttemptBudgetMS != resumeCap {
		t.Fatalf("resume budget readback=%+v", resumePayload)
	}
	if _, err := t3Claim(t, d, resumeTask, resumeCampaign, "readback-resume-expand", &expand); NativeCampaignErrorCode(err) != "budget_exhausted" {
		t.Fatalf("resume expanded claim code=%q", NativeCampaignErrorCode(err))
	}
	resumeClaim := t3MustClaim(t, d, resumeTask, resumeCampaign, "readback-resume-nil")
	if resumeClaim.Plan.ReservedBudgetMS != resumeCap || resumeClaim.Attempt.AttemptNo != 2 {
		t.Fatalf("resume nil claim plan=%+v attempt=%+v", resumeClaim.Plan, resumeClaim.Attempt)
	}
}

const t3SpecDefault10000 = `{"engine":"afl++","default_attempt_budget_ms":10000}`

func TestNativeCampaignPersistedDefaultAttemptBudget(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("start_omitted_uses_immutable_spec_default", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "default-start")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "default-start", t3SpecDefault10000, 600000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("default-start-start"), nil)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "default-start-instance", nil, 60000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 10000 || claim.Plan.ReservedBudgetMS != 10000 {
			t.Fatalf("persisted spec default ignored: attempt=%d plan=%d", claim.Attempt.ReservedBudgetMS, claim.Plan.ReservedBudgetMS)
		}
		if claim.Plan.ExecutionWindowMS != 5000 || claim.Plan.CleanupReserveMS != 5000 {
			t.Fatalf("default plan=%+v", claim.Plan)
		}
	})

	t.Run("caller_defaults_never_override_spec", func(t *testing.T) {
		for _, callerDefault := range []int64{0, 10000, 60000, 899999, 900000} {
			callerDefault := callerDefault
			t.Run(fmt.Sprintf("caller_%d", callerDefault), func(t *testing.T) {
				task, artifact := newNativeCampaignTask(t, d, fmt.Sprintf("default-caller-%d", callerDefault))
				campaign := t3CreateDraftWithSpec(t, d, task, artifact,
					fmt.Sprintf("default-caller-%d", callerDefault), t3SpecDefault10000, 600000)
				campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("default-caller-start"), nil)
				claim, err := t3ClaimWithCallerDefault(t, d, task, campaign,
					fmt.Sprintf("default-caller-instance-%d", callerDefault), nil, callerDefault)
				if err != nil {
					t.Fatal(err)
				}
				if claim.Attempt.ReservedBudgetMS != 10000 {
					t.Fatalf("caller default %d overrode spec: reserved=%d", callerDefault, claim.Attempt.ReservedBudgetMS)
				}
			})
		}
	})

	t.Run("spec_default_boundaries", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			spec  string
			total int64
			want  int64
		}{
			{"minimum_6000", `{"engine":"afl++","default_attempt_budget_ms":6000}`, 6000, 6000},
			{"maximum_900000", `{"engine":"afl++","default_attempt_budget_ms":900000}`, 900000, 900000},
		} {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				task, artifact := newNativeCampaignTask(t, d, "default-"+tc.name)
				campaign := t3CreateDraftWithSpec(t, d, task, artifact, "default-"+tc.name, tc.spec, tc.total)
				campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("default-boundary-start"), nil)
				claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "default-boundary-instance", nil, 60000)
				if err != nil {
					t.Fatal(err)
				}
				if claim.Attempt.ReservedBudgetMS != tc.want {
					t.Fatalf("boundary reserved=%d want %d", claim.Attempt.ReservedBudgetMS, tc.want)
				}
			})
		}
	})
}

func TestNativeCampaignDefaultBudgetExplicitCapPriority(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("explicit_start_cap_beats_spec_default", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cap-start")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "cap-start", t3SpecDefault10000, 600000)
		capValue := int64(30000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("cap-start-start"), &capValue)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "cap-start-instance", nil, 10000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != capValue {
			t.Fatalf("explicit start cap lost: reserved=%d want %d", claim.Attempt.ReservedBudgetMS, capValue)
		}
	})

	t.Run("claim_can_shrink_explicit_cap", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cap-shrink")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "cap-shrink", t3SpecDefault10000, 600000)
		capValue, smaller := int64(30000), int64(20000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("cap-shrink-start"), &capValue)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "cap-shrink-instance", &smaller, 60000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != smaller {
			t.Fatalf("claim could not shrink cap: reserved=%d want %d", claim.Attempt.ReservedBudgetMS, smaller)
		}
	})

	t.Run("claim_cannot_expand_explicit_cap", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cap-expand")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "cap-expand", t3SpecDefault10000, 600000)
		capValue, expand := int64(30000), int64(30001)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("cap-expand-start"), &capValue)
		if _, err := t3ClaimWithCallerDefault(t, d, task, campaign, "cap-expand-instance", &expand, 900000); NativeCampaignErrorCode(err) != "budget_exhausted" {
			t.Fatalf("expanded claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 0 {
			t.Fatalf("expanded claim created attempts: %d", got)
		}
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "cap-expand-nil", nil, 900000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != capValue {
			t.Fatalf("explicit cap not preserved after rejected expansion: %d", claim.Attempt.ReservedBudgetMS)
		}
	})

	t.Run("claim_cannot_expand_spec_default", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "spec-expand")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "spec-expand", t3SpecDefault10000, 600000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("spec-expand-start"), nil)
		expand := int64(10001)
		if _, err := t3ClaimWithCallerDefault(t, d, task, campaign, "spec-expand-instance", &expand, 60000); NativeCampaignErrorCode(err) != "budget_exhausted" {
			t.Fatalf("spec default expansion code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		if got := t3Count(t, d, "attempts", task.ID); got != 0 {
			t.Fatalf("spec default expansion created attempts: %d", got)
		}
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "spec-expand-nil", nil, 60000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 10000 {
			t.Fatalf("spec default not preserved after rejected expansion: %d", claim.Attempt.ReservedBudgetMS)
		}
	})

	t.Run("explicit_resume_cap_beats_spec_default", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "cap-resume")
		campaign, _ := t3PreparePausedCampaignWithSpec(t, d, task, artifact, "cap-resume", t3SpecDefault10000, 600000)
		resumeCap := int64(30000)
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("cap-resume-resume"),
			ExpectedStateVersion: campaign.StateVersion, AttemptBudgetMS: &resumeCap,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "cap-resume-instance", nil, 10000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != resumeCap || claim.Attempt.AttemptNo != 2 {
			t.Fatalf("resume cap lost: attempt=%+v", claim.Attempt)
		}
	})

	t.Run("resume_omitted_uses_spec_default", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "default-resume")
		campaign, _ := t3PreparePausedCampaignWithSpec(t, d, task, artifact, "default-resume", t3SpecDefault10000, 600000)
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("default-resume-resume"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "default-resume-instance", nil, 900000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 10000 || claim.Attempt.AttemptNo != 2 {
			t.Fatalf("resume default lost: attempt=%+v", claim.Attempt)
		}
	})
}

func TestNativeCampaignDefaultBudgetLegacySpec(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("missing_field_uses_fixed_60000", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "legacy-60000")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "legacy-60000", `{"engine":"afl++"}`, 600000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("legacy-60000-start"), nil)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "legacy-60000-instance", nil, 10000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != NativeCampaignCompatDefaultAttemptBudgetMS {
			t.Fatalf("legacy default=%d want %d", claim.Attempt.ReservedBudgetMS, NativeCampaignCompatDefaultAttemptBudgetMS)
		}
	})

	t.Run("missing_field_is_min_with_remaining", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "legacy-remaining")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "legacy-remaining", `{"engine":"afl++"}`, 6000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("legacy-remaining-start"), nil)
		claim, err := t3ClaimWithCallerDefault(t, d, task, campaign, "legacy-remaining-instance", nil, 900000)
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 6000 {
			t.Fatalf("legacy remaining default=%d want 6000", claim.Attempt.ReservedBudgetMS)
		}
	})
}

func TestNativeCampaignDefaultBudgetInvalidSpec(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	for _, tc := range []struct {
		name  string
		value string
	}{
		{"null", `null`},
		{"string", `"10000"`},
		{"fraction", `10000.5`},
		{"negative", `-1`},
		{"overflow", `9223372036854775808`},
		{"below_min", `5999`},
		{"above_max", `900001`},
		{"boolean", `true`},
		{"object", `{}`},
	} {
		tc := tc
		t.Run("start_rejects_"+tc.name, func(t *testing.T) {
			task, artifact := newNativeCampaignTask(t, d, "invalid-"+tc.name)
			spec := fmt.Sprintf(`{"engine":"afl++","default_attempt_budget_ms":%s}`, tc.value)
			campaign := t3CreateDraftWithSpec(t, d, task, artifact, "invalid-"+tc.name, spec, 600000)
			beforeEvents := t3Count(t, d, "events", task.ID)
			if _, err := d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
				TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("invalid-start"),
				ExpectedStateVersion: campaign.StateVersion,
			}); NativeCampaignErrorCode(err) != "invalid_request" {
				t.Fatalf("invalid %s start code=%q err=%v", tc.name, NativeCampaignErrorCode(err), err)
			}
			got := t3ReloadCampaign(t, d, campaign)
			if got.State != "draft" || got.StateVersion != campaign.StateVersion {
				t.Fatalf("invalid start changed campaign: %+v", got)
			}
			if t3Count(t, d, "events", task.ID) != beforeEvents {
				t.Fatal("invalid start wrote events")
			}
			for _, table := range []string{"attempts", "runs", "runtime"} {
				if count := t3Count(t, d, table, task.ID); count != 0 {
					t.Fatalf("invalid start left %s rows: %d", table, count)
				}
			}
		})
	}

	t.Run("resume_rejects_invalid_persisted_spec_without_side_effects", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "invalid-resume")
		spec := `{"engine":"afl++","default_attempt_budget_ms":null}`
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "invalid-resume", spec, 600000)
		// An explicit start cap does not consult the spec default, so it can
		// queue and run; the later resume without a cap must reject the bad
		// persisted default.
		capValue := int64(30000)
		campaign = t3Start(t, d, campaign, campaign.StateVersion, t3ReqID("invalid-resume-start"), &capValue)
		claim := t3MustClaim(t, d, task, campaign, "invalid-resume-instance")
		campaign = t3ReloadCampaign(t, d, campaign)
		if _, err := d.PauseNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("invalid-resume-pause"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign = t3ReloadCampaign(t, d, campaign)
		checkpoint := t3Checkpoint(t, d, task, campaign, claim.Attempt, "invalid-resume")
		evidence := t3Evidence(t, d, task, campaign, claim.Attempt)
		paused := t3MustFinalize(t, d, NativeCampaignFinalizeCommand{
			TaskID: task.ID, CampaignID: campaign.ID, AttemptID: claim.Attempt.ID,
			FencingToken: claim.Attempt.FencingToken, LeaseOwner: claim.Attempt.LeaseOwner,
			LeaseInstance: claim.Attempt.LeaseInstance, TargetState: "paused",
			CleanupStatus: "verified", CheckpointID: &checkpoint.ID, EvidenceID: evidence.ID,
			ActualElapsedMS: 4000, CleanupElapsedMS: 1000,
		})
		campaign = paused.Campaign
		beforeEvents := t3Count(t, d, "events", task.ID)
		beforeAttempts := t3Count(t, d, "attempts", task.ID)
		beforeRuns := t3Count(t, d, "runs", task.ID)
		beforeRuntime := t3Count(t, d, "runtime", task.ID)
		if _, err := d.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("invalid-resume-resume"),
			ExpectedStateVersion: campaign.StateVersion,
		}); NativeCampaignErrorCode(err) != "invalid_request" {
			t.Fatalf("invalid resume code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		got := t3ReloadCampaign(t, d, campaign)
		if got.State != "paused" || got.StateVersion != campaign.StateVersion || got.ChargedBudgetMS != campaign.ChargedBudgetMS {
			t.Fatalf("invalid resume changed campaign: %+v", got)
		}
		if t3Count(t, d, "events", task.ID) != beforeEvents ||
			t3Count(t, d, "attempts", task.ID) != beforeAttempts ||
			t3Count(t, d, "runs", task.ID) != beforeRuns ||
			t3Count(t, d, "runtime", task.ID) != beforeRuntime {
			t.Fatal("invalid resume left budget/run/attempt side effects")
		}
	})

	t.Run("claim_rejects_corrupt_persisted_spec_without_side_effects", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "invalid-claim")
		// The identity trigger forbids rewriting spec. Insert a queued legacy row
		// directly to model pre-field/corrupt persisted state that claim must
		// still reject instead of falling back to a caller default.
		spec := `{"engine":"afl++","default_attempt_budget_ms":null}`
		var campaignID int64
		if err := d.QueryRow(`INSERT INTO native_campaigns(
			task_id,artifact_id,spec,spec_hash,artifact_sha256,profile_id,image_digest,
			policy_revision,config_revision,state,desired_state,state_version,total_budget_ms,cleanup_status)
			VALUES($1,$2,$3,$4,$5,'lab-linux',$6,1,1,'queued','running',2,600000,'not_required')
			RETURNING id`,
			task.ID, artifact.ID, spec, nativeCampaignHash("invalid-claim-spec"),
			artifact.SHA256, "sha256:"+nativeCampaignHash("invalid-claim-image")).Scan(&campaignID); err != nil {
			t.Fatal(err)
		}
		campaign, err := d.NativeCampaign(context.Background(), task.ID, campaignID)
		if err != nil {
			t.Fatal(err)
		}
		beforeEvents := t3Count(t, d, "events", task.ID)
		if _, err := t3ClaimWithCallerDefault(t, d, task, campaign, "invalid-claim-instance", nil, 60000); NativeCampaignErrorCode(err) != "invalid_request" {
			t.Fatalf("corrupt spec claim code=%q err=%v", NativeCampaignErrorCode(err), err)
		}
		got := t3ReloadCampaign(t, d, campaign)
		if got.State != "queued" || got.StateVersion != campaign.StateVersion || got.ChargedBudgetMS != 0 {
			t.Fatalf("corrupt spec claim changed campaign: %+v", got)
		}
		if t3Count(t, d, "events", task.ID) != beforeEvents {
			t.Fatal("corrupt spec claim wrote events")
		}
		for _, table := range []string{"attempts", "runs", "runtime"} {
			if count := t3Count(t, d, table, task.ID); count != 0 {
				t.Fatalf("corrupt spec claim left %s rows: %d", table, count)
			}
		}
	})
}

func TestNativeCampaignDefaultBudgetAcrossReopen(t *testing.T) {
	dsn := fuzzTestDSN(t)
	d, err := Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	t.Run("start_after_reopen", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "reopen-start")
		campaign := t3CreateDraftWithSpec(t, d, task, artifact, "reopen-start", t3SpecDefault10000, 600000)
		reopened, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		campaign, err = reopened.NativeCampaign(context.Background(), task.ID, campaign.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("reopen-start-start"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign, err = reopened.NativeCampaign(context.Background(), task.ID, campaign.ID)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := reopened.ClaimNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignClaimCommand{
			TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: "reopen-start-instance",
			DefaultAttemptBudgetMS: 900000, ProfileMaxDurationMS: 600000,
			PolicyMaxDurationMS: 600000, OperatorKind: "admin",
		})
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 10000 {
			t.Fatalf("reopened start default=%d want 10000", claim.Attempt.ReservedBudgetMS)
		}
	})

	t.Run("resume_after_reopen", func(t *testing.T) {
		task, artifact := newNativeCampaignTask(t, d, "reopen-resume")
		campaign, _ := t3PreparePausedCampaignWithSpec(t, d, task, artifact, "reopen-resume", t3SpecDefault10000, 600000)
		reopened, err := Open(dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		campaign, err = reopened.NativeCampaign(context.Background(), task.ID, campaign.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reopened.ResumeNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: campaign.ID, RequestID: t3ReqID("reopen-resume-resume"),
			ExpectedStateVersion: campaign.StateVersion,
		}); err != nil {
			t.Fatal(err)
		}
		campaign, err = reopened.NativeCampaign(context.Background(), task.ID, campaign.ID)
		if err != nil {
			t.Fatal(err)
		}
		claim, err := reopened.ClaimNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignClaimCommand{
			TaskID: task.ID, CampaignID: campaign.ID, LeaseInstance: "reopen-resume-instance",
			DefaultAttemptBudgetMS: 900000, ProfileMaxDurationMS: 600000,
			PolicyMaxDurationMS: 600000, OperatorKind: "admin",
		})
		if err != nil {
			t.Fatal(err)
		}
		if claim.Attempt.ReservedBudgetMS != 10000 || claim.Attempt.AttemptNo != 2 {
			t.Fatalf("reopened resume attempt=%+v", claim.Attempt)
		}
	})
}
