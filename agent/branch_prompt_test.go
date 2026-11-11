package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestBranchPromptUsesNodeResponsibilities(t *testing.T) {
	for _, role := range []string{"planner", "worker", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer", "reviewer"} {
		t.Run(role, func(t *testing.T) {
			got := BranchPrompt(role, BuiltinPromptSeeds()[role], "fixture goal")
			if got == "" {
				t.Fatal("missing branch role")
			}
			for _, hostAPI := range []string{"add_intent", "prove_goal", "record_fact", "report_finding", "reverse_submit_conclusion", "reverse_review_conclusion", "{{.Goal}}", "成员独立复核"} {
				if strings.Contains(got, hostAPI) {
					t.Fatalf("host workflow leaked into %s: %s", role, hostAPI)
				}
			}
		})
	}
}

func TestBranchPromptPreservesCustomDomainInstructions(t *testing.T) {
	custom := "目标 {{.Goal}}。只分析指定材料；优先比较两个版本。"
	got := BranchPrompt("reverse_static", custom, "fixture")
	if got != "目标 fixture。只分析指定材料；优先比较两个版本。" {
		t.Fatalf("custom instruction lost: %q", got)
	}
	broken := "custom {{.FutureVariable}}"
	if got := BranchPrompt("worker", broken, "fixture"); got != broken {
		t.Fatalf("unknown custom template replaced: %q", got)
	}
}

func TestConstraintRulesDoNotBecomeAssetAllowlist(t *testing.T) {
	for _, rows := range [][]db.Constraint{
		{{Kind: "rule", Text: "每次请求间隔 2 秒"}},
		{{Kind: "deny", Text: "禁止中断业务"}},
		{{Kind: "allow", Text: "仅限 fixture.invalid"}, {Kind: "rule", Text: "报告脱敏"}},
	} {
		got := renderConstraints(rows)
		if strings.Contains(got, "除非它落在上述允许范围内") || !strings.Contains(got, "主任务已确认的资产范围") || !strings.Contains(got, "不是额外的资产白名单") {
			t.Fatalf("ambiguous scope framing: %s", got)
		}
		for _, c := range rows {
			if !strings.Contains(got, c.Text) {
				t.Fatalf("explicit constraint dropped: %q", c.Text)
			}
		}
	}
	if got := renderConstraints(nil); got != "" {
		t.Fatalf("empty constraints introduced instructions: %q", got)
	}
}
