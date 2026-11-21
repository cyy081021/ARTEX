package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// CTF mode's only deliverable is a flag, so a flag needs a home that is more than
// a free-form fact: a ledger with dedupe, a fact node the planner can see, and an
// API the operator can read. Without this the CTF overlay could only tell workers
// to "write the flag in a fact", and a repeated capture was indistinguishable from
// a first one.
//
// taskID may be 0 (tool seeding): the handler then resolves it from RunInfo, which
// keeps the seed rows and the runtime rows byte-identical.
func ctfFlagTools(pg *db.DB, taskID int64) []actool.CoreTool {
	record := func(ctx context.Context, raw json.RawMessage) (actool.Result, error) {
		if pg == nil {
			return actool.Errorf("flag 台账不可用：缺少数据库连接"), nil
		}
		var in struct {
			Flag     string `json:"flag"`
			Source   string `json:"source"`
			Note     string `json:"note"`
			IntentID int64  `json:"intent_id"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			return actool.Errorf("submit_flag 参数必须是 JSON 对象：flag/source/note/intent_id"), nil
		}
		if !agent.IsCTF(ctx) {
			return actool.Errorf("当前任务不是 CTF 模式；普通任务请把结论写成事实或结论，不要走 flag 台账"), nil
		}
		info := agent.RunInfoFrom(ctx)
		tid := taskID
		if tid <= 0 {
			tid = info.TaskID
		}
		if tid <= 0 {
			return actool.Errorf("submit_flag 缺少任务上下文"), nil
		}
		intentID := in.IntentID
		if intentID <= 0 {
			intentID = info.IntentID
		}
		flag, first, err := pg.AddTaskFlag(tid, intentID, in.Flag, in.Source, in.Note)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		out := map[string]any{
			"accepted":       true,
			"first_capture":  first,
			"duplicate":      !first,
			"flag_id":        flag.ID,
			"sha256":         flag.SHA256,
			"intent_id":      flag.IntentID,
			"recorded_at":    flag.CreatedAt,
			"next":           "把这条 flag 当作目标证据：用 record_fact 写一条 observed 事实（summary 写 flag 原文，evidence 写来源），然后让 planner 对该目标 prove_goal。",
			"authority_note": "flag 值与首次来源已落库；重复提交只返回 duplicate，不会覆盖首次来源。",
		}
		// A fact node makes the capture visible in the graph and lets a goal be
		// proven from real evidence instead of a tool message that disappears.
		if first {
			if st := storeForTask(pg, tid); st != nil {
				payload := map[string]any{
					"summary":    "捕获 flag：" + flag.Value,
					"detail":     firstNonEmptyString(in.Note, "flag 台账 #"+strconv.FormatInt(flag.ID, 10)),
					"evidence":   firstNonEmptyString(in.Source, "submit_flag"),
					"confidence": "observed",
				}
				if id, err := st.AddNode(db.KindFact, payload, 5, "confirmed", "worker", nil); err == nil {
					out["fact_id"] = id
					if intentID > 0 {
						_ = st.Link(intentID, db.RelYields, id)
					}
				}
			}
		}
		return jsonResult(out)
	}
	list := func(ctx context.Context, _ json.RawMessage) (actool.Result, error) {
		if pg == nil {
			return actool.Errorf("flag 台账不可用：缺少数据库连接"), nil
		}
		tid := taskID
		if tid <= 0 {
			tid = agent.RunInfoFrom(ctx).TaskID
		}
		if tid <= 0 {
			return actool.Errorf("list_flags 缺少任务上下文"), nil
		}
		flags, err := pg.ListTaskFlags(tid)
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		items := make([]map[string]any, 0, len(flags))
		for _, f := range flags {
			items = append(items, map[string]any{"id": f.ID, "value": f.Value, "sha256": f.SHA256, "source": f.Source, "note": f.Note, "intent_id": f.IntentID, "created_at": f.CreatedAt})
		}
		return jsonResult(map[string]any{"count": len(items), "flags": items})
	}
	return []actool.CoreTool{
		reverseTool("submit_flag",
			"记录一个已拿到的 CTF flag（比赛任务的唯一交付物）。首次捕获写入台账并生成一条 observed 事实；重复提交只返回 duplicate。flag 按原文精确比较；source 写清来源（请求/命令/响应片段），note 写影响或拿到的路径。",
			reverseObject(map[string]any{"flag": reverseString(), "source": reverseString(), "note": reverseString(), "intent_id": reverseInt()}, "flag"),
			record),
		reverseTool("list_flags",
			"列出本任务已捕获的 flag（值、来源、sha256、首次时间）。用来判断某个方向是否已经拿到 flag，避免重复劳动。",
			reverseObject(map[string]any{}),
			list),
	}
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// storeForTask returns the task's exploration store; nil when the task is unknown,
// in which case the flag is still recorded in the ledger.
func storeForTask(pg *db.DB, taskID int64) *db.ExplorationStore {
	if pg == nil || taskID <= 0 {
		return nil
	}
	task, err := pg.GetTask(taskID)
	if err != nil || task == nil || task.ExplorationID <= 0 {
		return nil
	}
	return pg.Exploration(task.ExplorationID)
}

// ctfFlagAllowed keeps the flag surface where a capture can actually happen; every
// role may read the ledger, only executing roles may write it.
func ctfFlagAllowed(agentKey, tool string) bool {
	switch tool {
	case "submit_flag":
		return agentKey == "worker" || agentKey == "reverse_static" || agentKey == "reverse_dynamic"
	case "list_flags":
		return true
	}
	return false
}

func (s *Server) ctfFlagRoutes(mux *http.ServeMux) {
	// Cross-task board: a competition runs many challenge tasks at once, so the
	// operator needs one place that lists every captured flag.
	mux.HandleFunc("GET /api/flags", func(w http.ResponseWriter, r *http.Request) {
		limit := 200
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				limit = n
			}
		}
		flags, e := s.m.pg.ListAllFlags(limit)
		if e != nil {
			writeErr(w, 500, e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"count": len(flags), "flags": flags})
	})
	mux.HandleFunc("GET /api/tasks/{id}/flags", func(w http.ResponseWriter, r *http.Request) {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil || id <= 0 {
			writeErr(w, 400, "invalid task id")
			return
		}
		flags, e := s.m.pg.ListTaskFlags(id)
		if e != nil {
			writeErr(w, 500, e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"task_id": id, "count": len(flags), "flags": flags})
	})
	// Operators also capture flags by hand while watching a competition; the same
	// ledger and the same dedupe apply, so a manual record cannot diverge from an
	// agent-recorded one.
	mux.HandleFunc("POST /api/tasks/{id}/flags", func(w http.ResponseWriter, r *http.Request) {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil || id <= 0 {
			writeErr(w, 400, "invalid task id")
			return
		}
		task, e := s.m.pg.GetTask(id)
		if e != nil || task == nil {
			writeErr(w, 404, "任务不存在")
			return
		}
		if task.Mode != "ctf" {
			writeErr(w, 409, "只有 CTF 模式的任务有 flag 台账；普通任务请把结论写成事实或结论")
			return
		}
		var in struct {
			Flag   string `json:"flag"`
			Source string `json:"source"`
			Note   string `json:"note"`
		}
		if !decodeConversationRequest(w, r, &in) {
			return
		}
		flag, first, e := s.m.pg.AddTaskFlag(id, 0, in.Flag, in.Source, in.Note)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"flag": flag, "first_capture": first, "duplicate": !first})
	})
}
