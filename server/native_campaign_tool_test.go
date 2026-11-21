package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// The durable campaign surface must exist as a real tool with a closed schema, and it
// must fail loudly rather than silently when the runtime is not configured on a server
// (the synchronous native_fuzz path stays available in that case).
func TestNativeCampaignToolSurface(t *testing.T) {
	tool := nativeCampaignTool(nil, &db.Task{ID: 1}, agent.RunInfo{IntentID: 2})
	if tool.Name() != "native_campaign" {
		t.Fatalf("tool name = %q", tool.Name())
	}
	schema := tool.InputSchema()
	if schema["additionalProperties"] != false {
		t.Fatal("campaign tool schema must reject unknown fields")
	}
	properties, _ := schema["properties"].(map[string]any)
	action, _ := properties["action"].(map[string]any)
	enum, _ := action["enum"].([]string)
	want := []string{"start", "status", "list", "pause", "resume", "cancel"}
	if len(enum) != len(want) {
		t.Fatalf("action enum = %v", enum)
	}
	for i := range want {
		if enum[i] != want[i] {
			t.Fatalf("action enum = %v", enum)
		}
	}
	for _, field := range []string{"campaign_id", "expected_state_version", "artifact_id", "profile_id", "seeds", "total_budget_ms", "attempt_budget_ms"} {
		if _, ok := properties[field]; !ok {
			t.Fatalf("missing schema field %q", field)
		}
	}

	// A nil service means the feature is off: the call must explain that instead of
	// pretending to queue a campaign.
	result, err := tool.Call(context.Background(), json.RawMessage(`{"action":"status","campaign_id":7}`), &actool.ToolContext{})
	if err != nil {
		t.Fatalf("tool call returned transport error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("unconfigured campaign runtime must be an error result: %+v", result)
	}
	text := result.Flatten()
	if !strings.Contains(text, "campaign runtime") || !strings.Contains(text, "native_fuzz") {
		t.Fatalf("unexpected unavailable payload: %q", text)
	}
}

// The seed table is the DB-level role gate: without a binding row ToolResolve drops the
// tool for every reverse role, so pin the dynamic-only binding.
func TestNativeCampaignToolSeededForDynamicOnly(t *testing.T) {
	var found bool
	for _, seed := range reverseToolDefaults(nil, t.TempDir()) {
		if seed.Key != reverseToolPrefix+"native_campaign" {
			continue
		}
		found = true
		if len(seed.Agents) != 1 || seed.Agents[0] != "reverse_dynamic" {
			t.Fatalf("native_campaign bound to %v, want [reverse_dynamic]", seed.Agents)
		}
		if seed.Desc == "" || seed.Schema == nil {
			t.Fatal("native_campaign seed has no description or schema")
		}
	}
	if !found {
		t.Fatal("native_campaign is not seeded")
	}
}
