package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/collab"
)

func TestReporterPromptSyncKnownDefaultAndUserEdits(t *testing.T) {
	s, _, _ := workflowFixture(t)
	a, err := s.m.pg.GetAgentByKey("reporter")
	if err != nil || a == nil {
		t.Fatalf("reporter fixture: %v", err)
	}
	legacy, err := os.ReadFile("testdata/reporter-baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Go raw strings discard CR; normalize a Windows checkout of the fixture.
	legacy = []byte(strings.ReplaceAll(string(legacy), "\r\n", "\n"))
	digest := sha256.Sum256(legacy)
	known := false
	for _, hash := range agent.LegacyBuiltinPromptHashes("reporter") {
		known = known || hash == hex.EncodeToString(digest[:])
	}
	if !known {
		t.Fatal("fixture does not match a recognized historical reporter default")
	}
	old, _ := s.m.pg.CurrentPrompt(a.ID)
	t.Cleanup(func() { _, _ = s.m.pg.SavePrompt(a.ID, old, "restore fixture", "system") })
	if _, err := s.m.pg.SavePrompt(a.ID, string(legacy), "legacy fixture", "system"); err != nil {
		t.Fatal(err)
	}
	_, _ = s.m.pg.Exec(`DELETE FROM agent_prompt_defaults WHERE agent_id=$1`, a.ID)
	s.syncReporterPrompt()
	if got, _ := s.m.pg.CurrentPrompt(a.ID); got != agent.ReporterDefaultPrompt {
		t.Fatal("known legacy default was not upgraded")
	}
	var before, after int
	_ = s.m.pg.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, a.ID).Scan(&before)
	s.syncReporterPrompt()
	_ = s.m.pg.QueryRow(`SELECT count(*) FROM agent_prompts WHERE agent_id=$1`, a.ID).Scan(&after)
	if before != after {
		t.Fatal("idempotent synchronization appended a duplicate version")
	}
	for _, edit := range []struct{ body, by string }{{string(legacy), "user"}, {"custom report style", "system"}} {
		if _, err := s.m.pg.SavePrompt(a.ID, edit.body, "custom fixture", edit.by); err != nil {
			t.Fatal(err)
		}
		s.syncReporterPrompt()
		if got, _ := s.m.pg.CurrentPrompt(a.ID); got != edit.body {
			t.Fatal("custom prompt was replaced")
		}
	}
}

func TestRetryToolDescriptionSyncPreservesConfiguration(t *testing.T) {
	s, _, _ := workflowFixture(t)
	for _, key := range []string{"retry_intent", "reverse__retry_intent"} {
		var oldDescription string
		var oldEnabled bool
		var oldAgents []byte
		if err := s.m.pg.QueryRow(`SELECT description,enabled,agents FROM tools WHERE key=$1`, key).Scan(&oldDescription, &oldEnabled, &oldAgents); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = s.m.pg.Exec(`UPDATE tools SET description=$2,enabled=$3,agents=$4::jsonb WHERE key=$1`, key, oldDescription, oldEnabled, string(oldAgents))
		})
		_, err := s.m.pg.Exec(`UPDATE tools SET description=$2,enabled=false,agents='[]'::jsonb WHERE key=$1`, key, agent.LegacyRetryIntentDescription)
		if err != nil {
			t.Fatal(err)
		}
		s.syncRetryToolDescription()
		var description string
		var enabled bool
		if err := s.m.pg.QueryRow(`SELECT description,enabled FROM tools WHERE key=$1`, key).Scan(&description, &enabled); err != nil || enabled || description != agent.RetryIntentDescription {
			t.Fatalf("known description sync changed configuration: %s %v", key, err)
		}
		_, _ = s.m.pg.Exec(`UPDATE tools SET description='custom retry instructions' WHERE key=$1`, key)
		s.syncRetryToolDescription()
		_ = s.m.pg.QueryRow(`SELECT description FROM tools WHERE key=$1`, key).Scan(&description)
		if description != "custom retry instructions" {
			t.Fatal("custom tool instructions overwritten")
		}
	}
}

func TestBranchSetupUsesPortableRolePrompts(t *testing.T) {
	f := newBranchSetupFixture(t)
	plan := f.preview(t)
	if len(plan.Blockers) != 0 {
		t.Fatalf("setup blocked: %v", plan.Blockers)
	}
	f.call(t, "/enable", map[string]any{"setup_token": plan.Token, "setup_options": plan.Options, "confirm": true}, 201)
	var raw []byte
	if err := f.s.m.pg.QueryRow(`SELECT state FROM team_branch_projects WHERE task_id=$1`, f.task).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored collab.BranchProject
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	for role, prompt := range map[string]string{"planner": stored.Policy.PlannerPrompts["pentest"], "worker": stored.Policy.Roles["worker"].SystemPrompt, "reviewer": stored.Policy.Roles["reviewer"].SystemPrompt} {
		for _, old := range []string{"add_intent", "prove_goal", "report_finding", "不能替代成员独立复核", "{{.Goal}}"} {
			if strings.Contains(prompt, old) {
				t.Fatalf("%s inherited host workflow %q", role, old)
			}
		}
		if !strings.Contains(prompt, "不得改变数据") {
			t.Fatalf("%s lost explicit project constraint", role)
		}
	}
}
