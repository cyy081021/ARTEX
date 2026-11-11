package collab

import (
	"encoding/json"
	"strconv"
	"testing"
)

func TestBranchAutomaticDispatchCapabilitiesLoadAndIdempotency(t *testing.T) {
	p := branchTestProject()
	p.Policy.Budget = 100
	p.Policy.AutoDispatch = true
	p.Policy.DeviceRoles = map[string]map[string][]string{"11": {"planner": {}, "worker": {"inspect"}, "reviewer": {"read_material"}}, "12": {"planner": {}, "worker": {"read_material"}, "reviewer": {"read_material"}}}
	devices := map[int64]BranchDevice{}
	for _, id := range []int64{11, 12} {
		devices[id] = BranchDevice{ID: id, OwnerID: 7, Active: true, Online: true, Protocol: 1, Roles: []string{"planner", "worker", "reviewer"}}
	}
	w := branchTestWork()
	w.Budget = 10
	w.RequiredCapabilities = map[string][]string{"worker": {"inspect"}}
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "publish", RequestID: "specific-tool", Work: &w})
	w.Title = "material review"
	w.RequiredCapabilities = map[string][]string{"worker": {"read_material"}}
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "publish", RequestID: "material", Work: &w})
	es, err := DispatchBranches(&p, devices, testTime())
	if err != nil {
		t.Fatal(err)
	}
	if len(es) == 0 || len(p.Branches) != 3 {
		t.Fatalf("dispatch=%+v err=%v", p, err)
	}
	if p.Branches[0].DeviceID != 11 || p.Branches[1].DeviceID != 12 {
		t.Fatalf("heterogeneous work mismatch: %+v", p.Branches)
	}
	count := len(p.Branches)
	es, err = DispatchBranches(&p, devices, testTime())
	if err != nil || len(es) != 0 || len(p.Branches) != count {
		t.Fatalf("dispatch replayed: %v %v", es, err)
	}
	w.Title = "wait for available inspect node"
	w.RequiredCapabilities = map[string][]string{"worker": {"inspect"}}
	branchDo(t, &p, BranchActor{Admin: true}, BranchCommand{Type: "publish", RequestID: "busy", Work: &w})
	if _, err = DispatchBranches(&p, devices, testTime()); err != nil {
		t.Fatal(err)
	}
	if p.Pool[len(p.Pool)-1].State != "published" {
		t.Fatal("busy device got extra work")
	}
	p.Branches[0].State = "accepted"
	if _, err = DispatchBranches(&p, devices, testTime()); err != nil {
		t.Fatal(err)
	}
	if p.Pool[len(p.Pool)-1].State != "claimed" {
		t.Fatal("available device did not receive work")
	}
}

func TestBranchAutomaticDispatchHonorsPauseAndApproval(t *testing.T) {
	p := branchTestProject()
	p.Policy.AutoDispatch = true
	p.State = "paused"
	if es, err := DispatchBranches(&p, nil, testTime()); err != nil || len(es) > 0 || len(p.Pool) > 0 {
		t.Fatal("paused project dispatched")
	}
	p.State = "running"
	p.Policy.AutoDispatch = false
	if es, err := DispatchBranches(&p, nil, testTime()); err != nil || len(es) > 0 {
		t.Fatal("manual project dispatched")
	}
}

func reviewFixture() (BranchProject, BranchActor) {
	p := branchTestProject()
	p.Policy.AutoReview = true
	worker := ExecutionResult{Version: 1, Role: "worker", Outcome: "candidate", Summary: "fixture observation", Evidence: []ExecutionEvidence{{ID: "e1", Tool: "inspect", Content: "observation", SHA256: ContentHash([]byte("observation"))}}}
	raw, _ := json.Marshal(worker)
	version := ContentHash(raw)
	reviewer := ExecutionResult{Version: 1, Role: "reviewer", Outcome: "candidate", Summary: "reviewed", Review: &BranchReviewAssessment{Decision: "accept", Reason: "证据对应目标，足以支持该项结论", AcceptanceMet: true, EvidenceVersions: map[string]string{"1": version}}}
	p.Branches = []ExecutionBranch{{ID: 1, TeamID: 2, TaskID: 9, OwnerID: 7, ControlID: 7, DeviceID: 11, Epoch: 1, State: "running", Spec: branchTestWork(), Contributors: []int64{7}, Units: []BranchUnit{
		{ID: 1, State: "candidate", Spec: BranchUnitSpec{Role: "worker"}, Result: &worker, EvidenceVersion: version},
		{ID: 2, State: "candidate", Spec: BranchUnitSpec{Role: "reviewer", DependsOn: []int64{1}}, Result: &reviewer, EvidenceVersion: "review-v1"},
	}}}
	return p, BranchActor{MemberID: 7, DeviceID: 11, Devices: map[int64]BranchDevice{11: {ID: 11, OwnerID: 7, Active: true, Online: true, Protocol: 1}}}
}

func TestBranchAutomaticReviewAcceptsClearAndEscalatesUnclear(t *testing.T) {
	for i, scenario := range []string{"accept", "uncertain", "changed_evidence", "no_evidence", "missing_review", "manual_policy"} {
		t.Run(scenario, func(t *testing.T) {
			p, node := reviewFixture()
			b := &p.Branches[0]
			switch scenario {
			case "uncertain":
				b.Units[1].Result.Review.Uncertainties = []string{"结果冲突"}
			case "changed_evidence":
				b.Units[1].Result.Review.EvidenceVersions["1"] = "old-version"
			case "no_evidence":
				b.Units[0].Result.Evidence = nil
			case "missing_review":
				b.Units[1].Result.Review = nil
			case "manual_policy":
				p.Policy.AutoReview = false
			}
			branchDo(t, &p, node, BranchCommand{Type: "submit", BranchID: 1, Epoch: 1, RequestID: "submit-" + strconv.Itoa(i), Outcome: "candidate", Text: "bounded result"})
			want := "review_pending"
			if scenario == "accept" {
				want = "accepted"
			}
			if b.State != want || p.State != "running" || len(b.Reviewers) != 0 {
				t.Fatalf("review changed wrong state: %+v", b)
			}
			if scenario != "manual_policy" && b.ReviewReason == "" {
				t.Fatal("automatic decision has no recorded reason")
			}
		})
	}
}
