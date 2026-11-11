package main

import (
	"os"
	"sort"

	"github.com/Autumn-27/artex/collab"
)

const (
	branchSetupIssueModelUnavailable = "model_unavailable"
	branchSetupIssuePlannerTools     = "planner_has_tools"
	branchSetupIssueToolMissing      = "tool_unconfigured"
	branchSetupIssueMCPServerMissing = "mcp_server_unconfigured"
	branchSetupIssueScopeMissing     = "scope_fields_missing"
	branchSetupIssueReadOnlyRequired = "read_only_required"
	branchSetupIssueRuntimeMissing   = "runtime_profile_unavailable"
)

// buildBranchSetupReport reports deterministic, configuration-only readiness.
// It never starts models, MCP servers, or configured commands.
func buildBranchSetupReport(cfg localExecutionConfig) collab.BranchSetupReport {
	report := collab.BranchSetupReport{Version: 1, Roles: make(map[string]collab.BranchSetupRole, len(cfg.Roles))}
	roleNames := make([]string, 0, len(cfg.Roles))
	for role := range cfg.Roles {
		roleNames = append(roleNames, role)
	}
	sort.Strings(roleNames)
	for _, role := range roleNames {
		local := cfg.Roles[role]
		entry := collab.BranchSetupRole{Capabilities: []string{}, Issues: []string{}}
		model, modelOK := cfg.Models[local.Model]
		if !modelOK || model.Model == "" || model.Endpoint == "" || model.APIKeyEnv == "" || os.Getenv(model.APIKeyEnv) == "" {
			entry.Ready = false
			entry.Issues = append(entry.Issues, branchSetupIssueModelUnavailable)
			report.Roles[role] = entry
			continue
		}
		entry.Ready = true
		if role == "planner" || role == "reverse_planner" {
			if len(local.Capabilities) != 0 {
				entry.Issues = append(entry.Issues, branchSetupIssuePlannerTools)
			}
			report.Roles[role] = entry
			continue
		}
		entry.Capabilities = append(entry.Capabilities, "read_material")
		for _, cap := range local.Capabilities {
			if cap == "read_material" {
				continue
			}
			if cap == reverseRuntimeCapability && role == "reverse_dynamic" {
				continue
			}
			command, isCommand := cfg.Commands[cap]
			mcp, isMCP := cfg.MCPTools[cap]
			if !isCommand && !isMCP {
				entry.Issues = append(entry.Issues, branchSetupIssueToolMissing)
				continue
			}
			if isMCP {
				if _, ok := cfg.MCPServers[mcp.Server]; !ok {
					entry.Issues = append(entry.Issues, branchSetupIssueMCPServerMissing)
					continue
				}
			}
			if len(cfg.Branches.ScopeFields[cap]) == 0 {
				entry.Issues = append(entry.Issues, branchSetupIssueScopeMissing)
				continue
			}
			if role != "worker" && ((isCommand && !command.ReadOnly) || (isMCP && !mcp.ReadOnly)) {
				entry.Issues = append(entry.Issues, branchSetupIssueReadOnlyRequired)
				continue
			}
			entry.Capabilities = append(entry.Capabilities, cap)
		}
		if role == "reverse_dynamic" {
			if branchSetupHasRuntimeProfile(cfg, local.RuntimeProfiles) {
				entry.Capabilities = append(entry.Capabilities, reverseRuntimeCapability)
			} else {
				entry.Issues = append(entry.Issues, branchSetupIssueRuntimeMissing)
			}
		}
		entry.Capabilities = uniqueSortedStrings(entry.Capabilities)
		entry.Issues = uniqueSortedStrings(entry.Issues)
		report.Roles[role] = entry
	}
	return report
}

func branchSetupHasRuntimeProfile(cfg localExecutionConfig, ids []string) bool {
	for _, id := range ids {
		if _, err := cfg.runtimeProfile(id); err == nil {
			return true
		}
	}
	return false
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
