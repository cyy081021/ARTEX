package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

// The agent-facing tool must drive the same service the HTTP layer uses: create a draft,
// queue it, and read it back. This is the integration point the role gate and schema tests
// cannot cover.
func TestNativeCampaignToolStartsThroughService(t *testing.T) {
	f := newT4AFixture(t, "tool-start")
	tool := nativeCampaignTool(f.service, f.task, agent.RunInfo{IntentID: 0, ExplorationID: 0})
	// The seed digest must be the digest of its own bytes: "AAAA" is the canonical fixture.
	const seedSHA = "63c1dd951ffedf6f7fd968ad4efa39b8ed584f162f46e715114ee184f8de9201"

	call := func(raw string) map[string]any {
		t.Helper()
		result, err := tool.Call(context.Background(), json.RawMessage(raw), &actool.ToolContext{})
		if err != nil {
			t.Fatalf("tool call transport error: %v", err)
		}
		text := result.Flatten()
		if result.IsError {
			t.Fatalf("tool returned error: %s", text)
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(text), &payload); err != nil {
			t.Fatalf("payload is not JSON: %v (%s)", err, text)
		}
		return payload
	}

	start := call(fmt.Sprintf(`{"action":"start","artifact_id":%d,"profile_id":%q,
		"seeds":[{"sha256":%q,"data_base64":"QUFBQQ=="}],
		"total_budget_ms":60000,"attempt_budget_ms":30000,"max_executions":1000}`,
		f.artifact.ID, f.profile.ID, seedSHA))
	campaignID := int64(0)
	if value, ok := start["campaign_id"].(float64); ok {
		campaignID = int64(value)
	}
	if campaignID <= 0 {
		t.Fatalf("start returned no campaign id: %v", start)
	}
	if start["state"] != "queued" {
		t.Fatalf("start state = %v, want queued", start["state"])
	}
	if start["candidate_only"] != true {
		t.Fatalf("start lost the candidate-only marker: %v", start)
	}

	status := call(fmt.Sprintf(`{"action":"status","campaign_id":%d}`, campaignID))
	if status["state"] != "queued" || int64(status["campaign_id"].(float64)) != campaignID {
		t.Fatalf("status mismatch: %v", status)
	}

	list := call(`{"action":"list","limit":10}`)
	rows, _ := list["campaigns"].([]any)
	found := false
	for _, row := range rows {
		item, _ := row.(map[string]any)
		if int64(item["campaign_id"].(float64)) == campaignID {
			found = true
		}
	}
	if !found {
		t.Fatalf("list does not contain campaign %d: %v", campaignID, list)
	}

	// Idempotence: the same intent calling start again must not create a second campaign.
	again := call(fmt.Sprintf(`{"action":"start","artifact_id":%d,"profile_id":%q,
		"seeds":[{"sha256":%q,"data_base64":"QUFBQQ=="}],
		"total_budget_ms":60000,"attempt_budget_ms":30000,"max_executions":1000}`,
		f.artifact.ID, f.profile.ID, seedSHA))
	if int64(again["campaign_id"].(float64)) != campaignID {
		t.Fatalf("retried start created a second campaign: %v vs %d", again, campaignID)
	}
}
