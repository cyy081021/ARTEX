package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// nativeCampaignTool exposes the durable campaign subsystem to reverse agents.
//
// native_fuzz stays the bounded synchronous path (and remains the fallback); this tool
// starts a campaign that survives a worker restart, can be paused, resumes from its
// checkpoint and charges budget from a durable ledger. Crashes stay candidates.
func nativeCampaignTool(svc *nativeCampaignService, task *db.Task, info agent.RunInfo) actool.CoreTool {
	schema := reverseObject(map[string]any{
		"action":                 map[string]any{"type": "string", "enum": []string{"start", "status", "list", "pause", "resume", "cancel"}},
		"campaign_id":            reverseInt(),
		"expected_state_version": reverseInt(),
		"artifact_id":            reverseInt(),
		"profile_id":             reverseString(),
		"argv":                   map[string]any{"type": "array", "items": reverseString()},
		"input_mode":             map[string]any{"type": "string", "enum": []string{"stdin", "file"}},
		"seeds":                  map[string]any{"type": "array", "items": reverseObject(map[string]any{"sha256": reverseString(), "data_base64": reverseString()}, "sha256", "data_base64")},
		"total_budget_ms":        reverseInt(),
		"attempt_budget_ms":      reverseInt(),
		"max_executions":         reverseInt(),
		"max_crashes":            reverseInt(),
		"limit":                  reverseInt(),
		"reason":                 reverseString(),
	}, "action")
	schema["additionalProperties"] = false
	description := "Persistent AFL++ campaign: start/status/list/pause/resume/cancel. " +
		"A campaign has a durable state machine, lease, budget ledger and corpus checkpoint, so it survives a worker restart and resumes from its checkpoint. " +
		"Crashes remain candidates: promote them only through native_case replay plus reviewer binding. " +
		"Poll with action=status no faster than once per 10 seconds. Use native_fuzz for one bounded synchronous run."
	return reverseTool("native_campaign", description, schema, func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if len(raw) > 64*1024 || !json.Valid(raw) {
			return actool.Errorf("invalid or oversized campaign request"), nil
		}
		var args campaignToolArgs
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&args); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if svc == nil || !svc.enabled {
			return actool.Errorf("campaign runtime is not configured on this server; use native_fuzz for a bounded synchronous run"), nil
		}
		if task == nil || task.ID <= 0 {
			return actool.Errorf("campaign tool requires a task"), nil
		}
		result, err := nativeCampaignToolAction(ctx, svc, task, info, args)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return reverseJSON(result), nil
	})
}

type campaignToolArgs struct {
	Action               string               `json:"action"`
	CampaignID           int64                `json:"campaign_id"`
	ExpectedStateVersion int64                `json:"expected_state_version"`
	ArtifactID           int64                `json:"artifact_id"`
	ProfileID            string               `json:"profile_id"`
	Argv                 []string             `json:"argv"`
	InputMode            string               `json:"input_mode"`
	Seeds                []nativeCampaignSeed `json:"seeds"`
	TotalBudgetMS        int64                `json:"total_budget_ms"`
	AttemptBudgetMS      int64                `json:"attempt_budget_ms"`
	MaxExecutions        int64                `json:"max_executions"`
	MaxCrashes           int                  `json:"max_crashes"`
	Limit                int                  `json:"limit"`
	Reason               string               `json:"reason"`
}

func nativeCampaignToolAction(ctx context.Context, svc *nativeCampaignService, task *db.Task, info agent.RunInfo, args campaignToolArgs) (any, error) {
	// Deterministic request ids keep a retried tool call idempotent instead of creating a
	// second campaign; the intent id keeps two intents independent.
	scope := fmt.Sprintf("%d-%d-%d", task.ID, info.IntentID, info.ExplorationID)
	switch args.Action {
	case "start":
		if args.ArtifactID <= 0 || args.ProfileID == "" {
			return nil, fmt.Errorf("start requires artifact_id and profile_id")
		}
		if len(args.Seeds) == 0 {
			return nil, fmt.Errorf("start requires at least one seed")
		}
		seeds, err := normalizeCampaignToolSeeds(args.Seeds)
		if err != nil {
			return nil, err
		}
		inputMode := args.InputMode
		if inputMode == "" {
			inputMode = "stdin"
		}
		total := args.TotalBudgetMS
		if total == 0 {
			total = 300000
		}
		attempt := args.AttemptBudgetMS
		if attempt == 0 {
			attempt = min(int64(120000), total)
		}
		maxExec := args.MaxExecutions
		if maxExec == 0 {
			maxExec = 100000
		}
		maxCrashes := args.MaxCrashes
		if maxCrashes == 0 {
			maxCrashes = 8
		}
		argv := args.Argv
		if argv == nil {
			argv = []string{}
		}
		fields := make(map[string]json.RawMessage, 12)
		put := func(key string, value any) {
			raw, _ := json.Marshal(value)
			fields[key] = raw
		}
		put("action", "create")
		put("request_id", "tool-create-"+scope)
		put("artifact_id", args.ArtifactID)
		put("profile_id", args.ProfileID)
		put("total_budget_ms", total)
		put("default_attempt_budget_ms", attempt)
		put("max_executions", maxExec)
		put("max_crashes", maxCrashes)
		put("input_mode", inputMode)
		put("argv", argv)
		put("seeds", seeds)
		created, err := svc.createHTTPDraft(ctx, task.ID, fields)
		if err != nil {
			return nil, err
		}
		var draft struct {
			Campaign *db.NativeCampaign `json:"campaign"`
		}
		if err := json.Unmarshal(created.Body, &draft); err != nil || draft.Campaign == nil {
			return nil, fmt.Errorf("campaign draft response is unreadable")
		}
		started, err := svc.Start(ctx, nativeCampaignStateCommand{
			TaskID: task.ID, CampaignID: draft.Campaign.ID,
			RequestID: "tool-start-" + scope, ExpectedStateVersion: draft.Campaign.StateVersion,
			ActorKind: "admin",
		})
		if err != nil {
			return nil, err
		}
		out := decodeCampaignBody(started.Body)
		out["next"] = "poll with action=status (>=10s apart); resume with action=resume after a pause"
		out["candidate_only"] = true
		return out, nil
	case "status":
		if args.CampaignID <= 0 {
			return nil, fmt.Errorf("status requires campaign_id")
		}
		campaign, err := svc.loadCampaign(ctx, task.ID, args.CampaignID)
		if err != nil {
			return nil, err
		}
		return campaignSummary(campaign), nil
	case "list":
		limit := args.Limit
		if limit <= 0 || limit > 50 {
			limit = 20
		}
		rows, err := svc.pg.NativeCampaigns(ctx, task.ID, limit, 0)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(rows))
		for i := range rows {
			out = append(out, campaignSummary(&rows[i]))
		}
		return map[string]any{"campaigns": out, "candidate_only": true}, nil
	case "pause", "resume", "cancel":
		if args.CampaignID <= 0 || args.ExpectedStateVersion <= 0 {
			return nil, fmt.Errorf("%s requires campaign_id and expected_state_version", args.Action)
		}
		reason := args.Reason
		if reason == "" {
			reason = "agent " + args.Action
		}
		requestID := fmt.Sprintf("tool-%s-%s-%d", args.Action, scope, time.Now().UnixNano()/int64(time.Millisecond))
		var (
			response *db.NativeCampaignCommandResponse
			err      error
		)
		switch args.Action {
		case "pause":
			response, err = svc.Pause(ctx, task.ID, args.CampaignID, reason, requestID)
		case "cancel":
			response, err = svc.Cancel(ctx, task.ID, args.CampaignID, reason, requestID)
		default:
			response, err = svc.Resume(ctx, nativeCampaignStateCommand{
				TaskID: task.ID, CampaignID: args.CampaignID, RequestID: requestID,
				ExpectedStateVersion: args.ExpectedStateVersion, ActorKind: "admin",
			})
		}
		if err != nil {
			return nil, err
		}
		out := decodeCampaignBody(response.Body)
		out["replayed"] = response.Replayed
		return out, nil
	default:
		return nil, fmt.Errorf("unknown campaign action %q", args.Action)
	}
}

func decodeCampaignBody(body json.RawMessage) map[string]any {	out := map[string]any{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	out["candidate_only"] = true
	out["authority"] = "candidate-only"
	return out
}

func campaignSummary(c *db.NativeCampaign) map[string]any {
	if c == nil {
		return map[string]any{"campaign": nil, "candidate_only": true}
	}
	return map[string]any{
		"campaign_id": c.ID, "state": c.State, "desired_state": c.DesiredState,
		"state_version": c.StateVersion, "profile_id": c.ProfileID,
		"total_budget_ms": c.TotalBudgetMS, "charged_budget_ms": c.ChargedBudgetMS,
		"cleanup_status": c.CleanupStatus, "latest_checkpoint_id": c.LatestCheckpointID,
		"current_attempt_id": c.CurrentAttemptID,
		"candidate_only":     true, "authority": "candidate-only",
	}
}
