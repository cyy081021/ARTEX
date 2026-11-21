package server

import (
	"context"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// The durable campaign tool must appear next to native_fuzz for the fuzzing role only,
// and must disappear again when the server has no campaign runtime. This pins the
// assembly gate (the DB seed row pins the role binding separately).
func TestReverseAgentToolsMountCampaignForDynamicOnly(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer m.Close()
	task, err := m.pg.CreateTaskWithOptions("campaign tool fixture", "expose campaigns", db.TaskCreateOptions{Kind: "reverse"})
	if err != nil {
		t.Fatal(err)
	}
	defer m.pg.DeleteTask(task.ID)

	has := func(tools []string, name string) bool {
		for _, tool := range tools {
			if tool == name {
				return true
			}
		}
		return false
	}
	names := func(role string, campaign *nativeCampaignService) []string {
		tools, _, closeTools := reverseAgentTools(context.Background(), m.pg, task, m.dir, role, campaign)
		defer closeTools()
		out := make([]string, 0, len(tools))
		for _, tool := range tools {
			out = append(out, tool.Name())
		}
		return out
	}

	service := &nativeCampaignService{enabled: true}
	if got := names("reverse_dynamic", service); !has(got, "native_campaign") || !has(got, "native_fuzz") {
		t.Fatalf("dynamic role must see both campaign and fuzz tools: %v", got)
	}
	if got := names("reverse_static", service); has(got, "native_campaign") {
		t.Fatalf("static role must not see the campaign tool: %v", got)
	}
	if got := names("reverse_dynamic", nil); has(got, "native_campaign") {
		t.Fatalf("campaign tool mounted without a runtime: %v", got)
	}
}
