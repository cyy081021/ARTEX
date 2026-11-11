package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/collab"
)

func TestAutoCoordinatorPlannerToolsAreIsolated(t *testing.T) {
	branch := &collab.ExecutionBranch{ID: 5, TaskID: 2, Epoch: 1, State: "running", Spec: collab.BranchWorkSpec{Coordinator: true}}
	var waiting, submitted, changed atomic.Bool
	cancelCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tools := branchPlannerTools(cancelCtx, localExecutionConfig{}, "https://coordinator.invalid", "token", nil, branch, collab.BranchPolicy{AutoDispatch: true}, nil, "", cancel, &waiting, &submitted, true, &changed)
	want := map[string]bool{"branch_wait": true, "propose_branch": true, "publish_branch": true}
	for _, tool := range tools {
		name := tool.Name()
		if !want[name] {
			t.Fatalf("unexpected coordinator tool %q", name)
		}
		delete(want, name)
	}
	if len(want) != 0 {
		t.Fatalf("coordinator tools missing: %v", want)
	}
	if branchCoordinatorHasUnits(branch) || !branchCoordinatorHasUnits(&collab.ExecutionBranch{Units: []collab.BranchUnit{{ID: 1}}}) {
		t.Fatal("coordinator unit execution guard does not distinguish empty and populated branches")
	}
}

func TestAutoCoordinatorSnapshotTracksExternalChangesOnly(t *testing.T) {
	coordinator := &collab.ExecutionBranch{ID: 9, Epoch: 3, Revision: 4, State: "running", Spec: collab.BranchWorkSpec{Coordinator: true, Kind: "pentest"}}
	other := collab.ExecutionBranch{ID: 10, WorkID: 2, Revision: 1, State: "running", Spec: collab.BranchWorkSpec{Title: "asset A"}}
	snapshot := &collab.BranchSnapshot{Cursor: 10, Events: []collab.BranchEvent{{Seq: 10, Text: "heartbeat"}}, Project: collab.BranchProject{
		Revision: 8,
		Pool:     []collab.BranchPoolWork{{ID: 2, State: "claimed", BranchID: 10, Spec: collab.BranchWorkSpec{Title: "asset A", Budget: 10}}},
		Branches: []collab.ExecutionBranch{{ID: coordinator.ID, Revision: coordinator.Revision, State: coordinator.State, Spec: coordinator.Spec}, other},
	}}
	policy := collab.BranchPolicy{AutoDispatch: true, Version: 2}
	first := branchPlannerSnapshotKey(coordinator, policy, nil, snapshot)
	coordinator.Revision++
	coordinator.State = "waiting_dependency"
	snapshot.Cursor++
	snapshot.Events = append(snapshot.Events, collab.BranchEvent{Seq: 11, Text: "another heartbeat"})
	snapshot.Project.Revision++
	snapshot.Project.Branches[0].Revision++ // Own operation/heartbeat churn is ignored.
	if got := branchPlannerSnapshotKey(coordinator, policy, nil, snapshot); got != first {
		t.Fatal("coordinator snapshot changed on own revision, state, or cursor churn")
	}
	snapshot.Project.Pool[0].State = "published"
	if got := branchPlannerSnapshotKey(coordinator, policy, nil, snapshot); got == first {
		t.Fatal("coordinator snapshot did not change when the work pool changed")
	}
	first = branchPlannerSnapshotKey(coordinator, policy, nil, snapshot)
	snapshot.Project.Branches[1].State = "accepted"
	snapshot.Project.Branches[1].Revision++
	snapshot.Project.Branches[1].Checkpoint = "independent review complete"
	if got := branchPlannerSnapshotKey(coordinator, policy, nil, snapshot); got == first {
		t.Fatal("coordinator snapshot did not change when an external branch changed")
	}
	first = branchPlannerSnapshotKey(coordinator, policy, nil, snapshot)
	snapshot.Project.Branches[1].Summary = "candidate evidence summary changed"
	snapshot.Project.Branches[1].ReviewMode = "automatic"
	snapshot.Project.Branches[1].ReviewReason = "acceptance confirmed"
	if got := branchPlannerSnapshotKey(coordinator, policy, nil, snapshot); got == first {
		t.Fatal("coordinator snapshot did not change when external result summary/review changed")
	}
}

func TestAutoCoordinatorInstructionBoundsDispatch(t *testing.T) {
	coordinator := &collab.ExecutionBranch{ID: 1, Spec: collab.BranchWorkSpec{Budget: 5}}
	child := collab.BranchWorkSpec{Roles: []string{"worker"}, RequiredCapabilities: map[string][]string{"worker": {"inspect"}}, Budget: 10}
	snapshot := &collab.BranchSnapshot{Project: collab.BranchProject{Policy: collab.BranchPolicy{Budget: 100}, Pool: []collab.BranchPoolWork{{State: "published", Spec: collab.BranchWorkSpec{Budget: 20}}}, Branches: []collab.ExecutionBranch{*coordinator}}}
	policy := collab.BranchPolicy{Budget: 100}
	message := branchCoordinatorInstruction(collab.BranchReply{Branch: coordinator, Policy: policy, Coordination: snapshot})
	for _, phrase := range []string{"required_capabilities", "never guess or set a device ID", "remaining amount", "independent member review", "publish_branch"} {
		if !strings.Contains(message, phrase) {
			t.Fatalf("coordinator prompt missing %q", phrase)
		}
	}
	if len(child.RequiredCapabilities["worker"]) != 1 {
		t.Fatal("test child work capability fixture invalid")
	}
	autoReview := branchCoordinatorInstruction(collab.BranchReply{Branch: coordinator, Policy: collab.BranchPolicy{Budget: 100, AutoReview: true}, Coordination: snapshot})
	if !strings.Contains(autoReview, "automatically accept clear") || strings.Contains(autoReview, "humans must independently review them") {
		t.Fatalf("coordinator prompt does not reflect automatic review: %s", autoReview)
	}
}

func TestAutoReviewInputContainsExactDependencyEvidence(t *testing.T) {
	evidenceVersion := strings.Repeat("a", 64)
	worker := collab.BranchUnit{ID: 7, State: "candidate", EvidenceVersion: evidenceVersion, Spec: collab.BranchUnitSpec{Role: "worker", Question: "check target", Contract: json.RawMessage(`{"acceptance":["response is bounded"]}`)}, Result: &collab.ExecutionResult{Version: 1, Outcome: "candidate", Summary: "observed bounded response", Role: "worker", Evidence: []collab.ExecutionEvidence{{ID: "ev1", Tool: "inspect", SHA256: strings.Repeat("b", 64), Content: "response bounded"}}}}
	reviewer := collab.BranchUnitSpec{Role: "reviewer", Question: "independently verify", DependsOn: []int64{7}, Contract: json.RawMessage(`{"acceptance":["review source evidence"]}`)}
	branch := &collab.ExecutionBranch{Units: []collab.BranchUnit{worker}}
	raw := branchUnitInput(reviewer, branch, collab.BranchPolicy{AutoReview: true}, nil, branch)
	var input map[string]any
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatal(err)
	}
	targets, ok := input["automatic_review_targets"].([]any)
	if !ok || len(targets) != 1 {
		t.Fatalf("missing automatic review targets: %s", raw)
	}
	target := targets[0].(map[string]any)
	if target["unit_id"] != float64(7) || target["evidence_version"] != evidenceVersion || target["acceptance"] == nil || target["result"] == nil {
		t.Fatalf("review target lacks identity, evidence, acceptance, or result: %+v", target)
	}
	workerRaw := branchUnitInput(collab.BranchUnitSpec{Role: "worker", Question: "do work"}, &collab.ExecutionBranch{Units: []collab.BranchUnit{worker}}, collab.BranchPolicy{AutoReview: true}, nil)
	if strings.Contains(workerRaw, "automatic_review_targets") || strings.Contains(workerRaw, `"review"`) {
		t.Fatalf("worker was given review output instructions: %s", workerRaw)
	}
}

func TestParseBranchReviewFinalStrictAndOptional(t *testing.T) {
	valid := `{"outcome":"candidate","summary":"reviewed","review":{"decision":"accept","reason":"Evidence meets criteria","acceptance_met":true,"evidence_versions":{"7":"` + strings.Repeat("a", 64) + `"},"uncertainties":[]}}`
	assessment, err := parseBranchReviewFinal(valid)
	if err != nil || assessment.Decision != "accept" || !assessment.AcceptanceMet || assessment.EvidenceVersions["7"] != strings.Repeat("a", 64) {
		t.Fatalf("valid review rejected: %+v %v", assessment, err)
	}
	needsHuman := strings.Replace(valid, `"decision":"accept"`, `"decision":"needs_human"`, 1)
	if assessment, err = parseBranchReviewFinal(needsHuman); err != nil || assessment.Decision != "needs_human" {
		t.Fatalf("needs_human review rejected: %+v %v", assessment, err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, `"decision":"accept"`, `"decision":"auto_accept"`, 1),
		strings.Replace(valid, `"evidence_versions":{"7":"`+strings.Repeat("a", 64)+`"}`, `"evidence_versions":{"bad":"x"}`, 1),
		strings.TrimSuffix(valid, "}") + ` trailing}`,
		strings.Replace(valid, `"review":{`, `"review":{"unexpected":true,`, 1),
	} {
		if _, err := parseBranchReviewFinal(invalid); err == nil {
			t.Fatalf("invalid review accepted: %s", invalid)
		}
	}
	missingReview := `{"outcome":"candidate","summary":"ordinary result"}`
	if outcome, _, err := parseBranchUnitFinal(missingReview); err != nil || outcome != "candidate" {
		t.Fatalf("missing optional review made normal result invalid: %s %v", outcome, err)
	}
	if _, err := parseBranchReviewFinal(missingReview); err == nil {
		t.Fatal("missing review assessment parsed as automatic review")
	}
}
