package agent

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/collab"
)

// BranchPrompt replaces recognized shipped host templates with the branch
// protocol equivalent. User-authored domain instructions remain intact.
func BranchPrompt(role, configured, goal string) string {
	configured = strings.TrimSpace(configured)
	known := configured == "" || configured == strings.TrimSpace(BuiltinPromptSeeds()[role])
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(configured)))
	for _, legacy := range LegacyBuiltinPromptHashes(role) {
		known = known || hash == legacy
	}
	if known {
		return collab.BranchRolePrompt(role)
	}
	// Render the existing template vocabulary, without adding host credentials
	// or filesystem paths to a portable branch policy.
	vars := map[string]string{"Goal": goal, "Scope": "", "AssetSummary": "", "FindingsSummary": "", "DataDir": "", "WorkDir": "", "ProxyAddr": "", "WorkerName": role, "EngagementDescription": "", "Now": nowStr()}
	if rendered, err := renderTmpl(configured, vars); err == nil {
		return rendered
	}
	return configured
}
