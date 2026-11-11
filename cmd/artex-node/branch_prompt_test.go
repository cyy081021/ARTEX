package main

import (
	"strings"
	"testing"
)

func TestBranchToolProtocolUsesCurrentSubmissionAndReviewMode(t *testing.T) {
	planner := branchToolProtocol(nil, true, false, true)
	for _, want := range []string{"propose_work", "branch_wait", "submit_branch", "以本节和当前工具 schema 为准"} {
		if !strings.Contains(planner, want) {
			t.Fatalf("planner missing %q", want)
		}
	}
	auto := branchToolProtocol(nil, false, true, true)
	for _, want := range []string{"final_format", "节点负责结果与证据回传", "不再另等成员逐项确认", "needs_human"} {
		if !strings.Contains(auto, want) {
			t.Fatalf("automatic reviewer missing %q", want)
		}
	}
	manual := branchToolProtocol(nil, false, true, false)
	if !strings.Contains(manual, "当前使用人工复核") || strings.Contains(manual, "当前启用自动核验") {
		t.Fatal("manual review policy was overridden")
	}
	worker := branchToolProtocol(nil, false, false, true)
	if strings.Contains(worker, "当前启用自动核验") {
		t.Fatal("executor was instructed to accept its own result")
	}
}
