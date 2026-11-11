package main

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestBranchSetupReportFiltersConfiguredCapabilities(t *testing.T) {
	t.Setenv("BRANCH_SETUP_REPORT_TEST_KEY", "synthetic")
	cfg := localExecutionConfig{
		Roles: map[string]localRoleConfig{
			"reviewer": {Model: "model", Capabilities: []string{"unsafe", "missing", "no_scope", "mcp", "safe"}},
			"worker":   {Model: "missing-model", Capabilities: []string{"safe"}},
		},
		Models: map[string]localModelConfig{"model": {Endpoint: "https://example.invalid", Model: "fixture", APIKeyEnv: "BRANCH_SETUP_REPORT_TEST_KEY"}},
		Commands: map[string]localCommandConfig{
			"unsafe":   {ReadOnly: false},
			"no_scope": {ReadOnly: true},
			"safe":     {ReadOnly: true},
		},
		MCPTools:   map[string]localMCPTool{"mcp": {Server: "server", Tool: "tool", ReadOnly: true}},
		MCPServers: map[string]localMCPServer{"server": {Command: "/not-executed"}},
		Branches:   localBranchConfig{ScopeFields: map[string][]string{"unsafe": {"target"}, "mcp": {"url"}, "safe": {"target"}}},
	}
	report := buildBranchSetupReport(cfg)
	if report.Version != 1 || !reflect.DeepEqual(report.Roles["worker"].Capabilities, []string{}) || report.Roles["worker"].Ready {
		t.Fatalf("unexpected worker report: %+v", report.Roles["worker"])
	}
	reviewer := report.Roles["reviewer"]
	if !reviewer.Ready || !reflect.DeepEqual(reviewer.Capabilities, []string{"mcp", "read_material", "safe"}) {
		t.Fatalf("unexpected reviewer report: %+v", reviewer)
	}
	for _, code := range []string{branchSetupIssueToolMissing, branchSetupIssueScopeMissing, branchSetupIssueReadOnlyRequired} {
		if !containsString(reviewer.Issues, code) {
			t.Fatalf("missing issue %q in %+v", code, reviewer.Issues)
		}
	}
}

func TestBranchSetupReportPlannerAndDynamicRuntime(t *testing.T) {
	t.Setenv("BRANCH_SETUP_REPORT_TEST_KEY", "synthetic")
	cfg := localExecutionConfig{
		Roles: map[string]localRoleConfig{
			"planner":         {Model: "model", Capabilities: []string{"leak"}},
			"reverse_dynamic": {Model: "model", RuntimeProfiles: []string{"valid"}},
		},
		Models:          map[string]localModelConfig{"model": {Endpoint: "https://example.invalid", Model: "fixture", APIKeyEnv: "BRANCH_SETUP_REPORT_TEST_KEY"}},
		RuntimeProfiles: map[string]localRuntimeProfile{"valid": {Name: "fixture", Platform: "linux", Command: "/not-executed", MaxDurationMS: 100}},
	}
	report := buildBranchSetupReport(cfg)
	if len(report.Roles["planner"].Capabilities) != 0 || !containsString(report.Roles["planner"].Issues, branchSetupIssuePlannerTools) {
		t.Fatalf("planner tools not excluded: %+v", report.Roles["planner"])
	}
	dynamic := report.Roles["reverse_dynamic"]
	if !containsString(dynamic.Capabilities, "read_material") || !containsString(dynamic.Capabilities, reverseRuntimeCapability) {
		t.Fatalf("valid runtime profile not reported: %+v", dynamic)
	}
}

func TestBranchSetupReportDoesNotExposeSecretsOrExecuteTools(t *testing.T) {
	secret := "never-serialize-secret"
	keyName := "BRANCH_SETUP_REPORT_SECRET_ENV_NAME"
	t.Setenv(keyName, secret)
	cfg := localExecutionConfig{
		Roles:    map[string]localRoleConfig{"worker": {Model: "model", Capabilities: []string{"safe"}}},
		Models:   map[string]localModelConfig{"model": {Endpoint: "https://private.invalid/path", Model: "fixture-model-secret", APIKeyEnv: keyName}},
		Commands: map[string]localCommandConfig{"safe": {ReadOnly: true, Command: "/must-not-run"}},
		Branches: localBranchConfig{ScopeFields: map[string][]string{"safe": {"target"}}},
	}
	raw, err := json.Marshal(buildBranchSetupReport(cfg))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, keyName, "private.invalid", "fixture-model-secret", "/must-not-run"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("report leaked %q: %s", forbidden, raw)
		}
	}
	if _, err := os.Stat("/must-not-run"); !os.IsNotExist(err) {
		t.Fatalf("unexpected side effect path state: %v", err)
	}
}

func TestBranchSetupReportMissingModelKey(t *testing.T) {
	t.Setenv("BRANCH_SETUP_REPORT_TEST_KEY", "")
	cfg := localExecutionConfig{Roles: map[string]localRoleConfig{"worker": {Model: "model"}}, Models: map[string]localModelConfig{"model": {Endpoint: "x", Model: "m", APIKeyEnv: "BRANCH_SETUP_REPORT_TEST_KEY"}}}
	report := buildBranchSetupReport(cfg)
	entry := report.Roles["worker"]
	if entry.Ready || len(entry.Capabilities) != 0 || !containsString(entry.Issues, branchSetupIssueModelUnavailable) {
		t.Fatalf("missing key should make role not ready: %+v", entry)
	}
}
