package agent

import (
	"strings"
	"testing"
)

// The software workflow must explore for vulnerabilities instead of only
// answering questions. These assertions pin the policy text that encodes that:
// if someone softens it back to "解释即可，不要求发现漏洞", the test fails.
func TestSoftwareExplorationPolicyPrompts(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
		not  []string
	}{
		{
			name: "common",
			body: reverseCommon,
			want: []string{"漏洞", "开源", "闭源", "独立核验", "不存在漏洞"},
			not:  []string{"不要求发现漏洞"},
		},
		{
			name: "goals",
			body: reverseGoalsDefaultTmpl,
			want: []string{"vulnclass", "攻击面", "可量化"},
			not:  []string{"vulnclass 留空"},
		},
		{
			name: "planner",
			body: reversePlannerDefaultTmpl,
			want: []string{"硬底线", "record_planning_decision", "reverse_static", "reverse_dynamic", "reverse_reviewer", "开源", "闭源"},
			not:  []string{"只生成有界工作单"},
		},
		{
			name: "static",
			body: reverseStaticDefaultTmpl,
			want: []string{"不执行目标程序", "native_inspect", "reverse_submit_conclusion"},
			not:  []string{"回答问题"},
		},
		{
			name: "dynamic",
			body: reverseDynamicDefaultTmpl,
			want: []string{"native_case", "native_fuzz", "恢复条件"},
			not:  []string{"观察一次"},
		},
		{
			name: "reviewer",
			body: reverseReviewerDefaultTmpl,
			want: []string{"独立核验者", "核验自己的结论"},
		},
	}
	for _, c := range cases {
		for _, want := range c.want {
			if !strings.Contains(c.body, want) {
				t.Errorf("%s prompt lost %q", c.name, want)
			}
		}
		for _, bad := range c.not {
			if strings.Contains(c.body, bad) {
				t.Errorf("%s prompt still says %q", c.name, bad)
			}
		}
	}
}

// The pentest planner keeps the same hard floor restored from the baseline: with
// a goal still open and nothing in play, the round may not end with zero intents.
func TestPlannerPromptKeepsHardFloor(t *testing.T) {
	if !strings.Contains(plannerDefaultTmpl, "硬底线") {
		t.Fatal("planner prompt lost the hard floor")
	}
	if !strings.Contains(plannerDefaultTmpl, "必须") {
		t.Fatal("planner prompt must demand at least one intent")
	}
	if strings.Contains(plannerDefaultTmpl, "产出 0 意图=正常") {
		t.Fatal("planner prompt must not present stalling as normal")
	}
}

// Software workflow keeps the boundary that makes its conclusions trustworthy:
// exploration needs the native tools, but native jobs cannot escape through
// skills/MCP, and findings still need the reviewer + replay path.
func TestSoftwareExplorationToolBoundary(t *testing.T) {
	for _, name := range []string{"native_inspect", "native_case", "native_fuzz", "native_publish_finding"} {
		if !ReverseToolAllowed(name) {
			t.Fatalf("%s must stay available to the software workflow", name)
		}
	}
	if NativeToolAllowed("Skill") || NativeToolAllowed("mcp__server__tool") {
		t.Fatal("native jobs must not escape through skills or MCP")
	}
}
