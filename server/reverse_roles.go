package server

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
)

const reverseToolPrefix = "reverse__"

// Namespace configuration, not handler names. Both workflows can reuse a tool
// implementation without sharing enable flags, descriptions or defaults.
func reverseToolDefaults(pg *db.DB, dir string) []agent.ToolSeed {
	seeds := []agent.ToolSeed{}
	for _, sd := range agent.BuiltinToolSeeds() {
		if !agent.ReverseToolAllowed(sd.Key) {
			continue
		}
		roles := []string{}
		for _, legacy := range sd.Agents {
			switch legacy {
			case "mainagent":
				roles = append(roles, "reverse_main")
			case "planner":
				roles = append(roles, "reverse_planner")
			case "goals":
				roles = append(roles, "reverse_goals")
			case "worker":
				roles = append(roles, "reverse_static", "reverse_dynamic", "reverse_reviewer")
			}
		}
		sd.Key = reverseToolPrefix + sd.Key
		sd.Agents = roles
		seeds = append(seeds, sd)
	}
	for _, t := range actool.DefaultTools() {
		if !agent.ReverseToolAllowed(t.Name()) {
			continue
		}
		seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + t.Name(), Desc: t.Description(), Schema: t.InputSchema(), Agents: []string{"reverse_main", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer"}})
	}
	tools, _, close := reverseAgentTools(context.Background(), pg, &db.Task{}, dir, "worker", nil)
	defer close()
	for _, t := range tools {
		roles := []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"}
		switch t.Name() {
		case "reverse_workspace":
			roles = []string{"reverse_main", "reverse_goals", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer"}
		case "reverse_submit_conclusion":
			roles = []string{"reverse_static", "reverse_dynamic"}
		case "reverse_review_conclusion", "native_review", "native_publish_finding":
			roles = []string{"reverse_reviewer"}
		case "native_fuzz":
			roles = []string{"reverse_dynamic"}
		case "native_session", "native_case", "reverse_observe_runtime", "reverse_runtime_session", "reverse_browser_scenario":
			roles = []string{"reverse_dynamic", "reverse_reviewer"}
		case "reverse_get_conclusion", "reverse_read_evidence", "reverse_read_derived", "reverse_inspect_hermes":
			roles = []string{"reverse_main", "reverse_goals", "reverse_planner", "reverse_static", "reverse_dynamic", "reverse_reviewer"}
		case "reverse_prepare_apk":
			roles = []string{"reverse_static", "reverse_dynamic"}
		}
		seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + t.Name(), Desc: t.Description(), Schema: t.InputSchema(), Agents: roles})
	}
	// The worker enumeration above intentionally lists the broad tool set; the
	// fuzz action is only authorized for the dynamic role and is seeded here.
	fuzz := nativeFuzzTool(pg, &db.Task{}, agent.RunInfo{}, dir)
	seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + fuzz.Name(), Desc: fuzz.Description(), Schema: fuzz.InputSchema(), Agents: []string{"reverse_dynamic"}})
	// The durable campaign tool is mounted next to native_fuzz for the same role, so it
	// needs its own binding row for ToolResolve to keep it.
	campaignSeed := nativeCampaignTool(nil, &db.Task{}, agent.RunInfo{})
	seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + campaignSeed.Name(), Desc: campaignSeed.Description(), Schema: campaignSeed.InputSchema(), Agents: []string{"reverse_dynamic"}})
	// sandbox_exec is built outside the worker enumeration above (it lives in
	// nativeTools behind a role switch), so without an explicit seed row the DB
	// has no binding and ToolResolve drops it for every reverse role.
	execTool := reverseExecTool(&db.Task{}, agent.RunInfo{}, dir, "reverse_static")
	seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + execTool.Name(), Desc: execTool.Description(), Schema: execTool.InputSchema(), Agents: []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"}})
	// CTF 模式的 flag 台账工具同样由 ToolAugment 提供；逆向任务只在 CTF 模式下追加，
	// 但没有 DB 行时 ToolResolve 会把未知名字丢掉，所以这里必须显式 seed。
	for _, t := range ctfFlagTools(nil, 0) {
		seeds = append(seeds, agent.ToolSeed{Key: reverseToolPrefix + t.Name(), Desc: t.Description(), Schema: t.InputSchema(), Agents: []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"}})
	}
	return seeds
}

func seedReverseRoles(pg *db.DB, dir string) error {
	for _, sd := range reverseToolDefaults(pg, dir) {
		schema, _ := json.Marshal(sd.Schema)
		binds, _ := json.Marshal(sd.Agents)
		if err := pg.SeedTool(sd.Key, sd.Desc, schema, binds); err != nil {
			return err
		}
		// A row created before this tool existed, or created by hand, may carry an
		// empty agent list, which silently hides the tool from every reverse role.
		if err := pg.EnsureToolAgents(sd.Key, binds); err != nil {
			return err
		}
		if sd.Key == reverseToolPrefix+"complete_intent" {
			// Preserve operator bindings/defaults while adding the new protocol
			// field to existing installations (SeedTool never overwrites rows).
			properties, _ := sd.Schema["properties"].(map[string]any)
			if field, ok := properties["satisfied_ids"]; ok {
				if err := pg.EnsureToolSchemaFields(sd.Key, map[string]any{"satisfied_ids": field}, nil); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *Server) workflowRoleAvailable(t *Task, key string) bool {
	if t == nil {
		return false
	}
	if t.Kind == "reverse" {
		a, err := s.m.pg.GetAgentByKey(key)
		if err != nil || a == nil || !a.Enabled {
			return false
		}
	}
	return true
}

func (s *Server) workerForIntent(t *Task, intent *db.Node) (*agent.Worker, error) {
	if t.Kind != "reverse" {
		return s.agentsForTask(t).wk, nil
	}
	contract, _ := db.IntentContract(intent)
	key, err := agent.ReverseWorkerKey(contract.ExecutionRole)
	if err != nil {
		return nil, err
	}
	if !s.taskRuntimeAvailable(t, key) {
		return nil, fmt.Errorf("逆向角色 %s 已停用或模型不可用", key)
	}
	return s.agentsForTask(t).workers[key], nil
}

func permittedReverseRoleTool(key, name string) bool {
	if !strings.HasPrefix(key, "reverse_") {
		return true
	}
	switch name {
	case "reverse_submit_conclusion":
		return key == "reverse_static" || key == "reverse_dynamic"
	case "reverse_review_conclusion", "native_review", "native_publish_finding":
		return key == "reverse_reviewer"
	case "native_fuzz", "native_campaign":
		return key == "reverse_dynamic"
	case "native_inspect":
		return key == "reverse_static" || key == "reverse_dynamic" || key == "reverse_reviewer"
	case "sandbox_exec":
		return key == "reverse_static" || key == "reverse_dynamic" || key == "reverse_reviewer"
	case "native_session", "native_case", "reverse_observe_runtime", "reverse_runtime_session", "reverse_browser_scenario":
		return key == "reverse_dynamic" || key == "reverse_reviewer"
	case "reverse_prepare_apk":
		return key == "reverse_static" || key == "reverse_dynamic"
	case "reverse_inspect_hermes", "reverse_read_derived":
		return key == "reverse_static" || key == "reverse_dynamic" || key == "reverse_reviewer"
	}
	if strings.HasPrefix(name, "native_") {
		return false
	}
	return true
}

func (s *Server) recordAgentConfiguration(t *Task, key string, intentID int64) {
	if t == nil || s.m.pg == nil {
		return
	}
	a, err := s.m.pg.GetAgentByKey(key)
	if err != nil || a == nil {
		return
	}
	prompt, _ := s.m.pg.CurrentPrompt(a.ID)
	promptHash := sha256.Sum256([]byte(prompt))
	tools, _ := s.m.pg.ListTools()
	bound := []*db.Tool{}
	for _, tool := range tools {
		if contains(tool.Agents, key) {
			bound = append(bound, tool)
		}
	}
	mcps, _ := s.m.pg.AgentVisible(a.ID, "mcp")
	skills, _ := s.m.pg.AgentSkillNames(a.ID)
	snapshot := map[string]any{"agent": a, "prompt_sha256": fmt.Sprintf("%x", promptHash), "tools": bound, "mcp_bindings": mcps, "skill_bindings": skills}
	raw, _ := json.Marshal(snapshot)
	hash := sha256.Sum256(raw)
	metadata, _ := json.Marshal(map[string]any{"agent_config": map[string]any{"key": key, "revision": fmt.Sprintf("%x", hash), "prompt_sha256": fmt.Sprintf("%x", promptHash), "max_turns": a.MaxTurns, "run_seconds": a.RunSecs, "llm_profile_id": a.LLMProfileID}})
	worker := "planner"
	if key == "mainagent" || key == "reverse_main" {
		worker = "mainagent"
	}
	activity := db.Activity{Worker: worker, Kind: "agent_config", Summary: "执行角色：" + key, Metadata: metadata}
	if intentID > 0 {
		activity.NodeID = &intentID
		if n, err := t.Store.GetNode(intentID); err == nil && n != nil {
			activity.Worker = n.Owner
		}
	}
	s.engine.emitActivity(t, activity)
}
