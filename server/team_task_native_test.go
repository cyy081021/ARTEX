package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTeamTaskNativeScopeAndShapes(t *testing.T) {
	f := newTeamContentFixture(t)
	host := httptest.NewTLSServer(f.s.TeamHandler())
	defer host.Close()
	get := func(path, method string, want int) []byte {
		t.Helper()
		req, _ := http.NewRequest(method, host.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+f.token)
		resp, err := host.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, body)
		}
		if want == 200 && resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("native member response must be no-store")
		}
		return body
	}
	nativeFor := func(taskID, path string) string {
		prefix := fmt.Sprintf("/api/teams/%d/tasks/%s", f.team, taskID)
		return prefix + "/native?path=" + url.QueryEscape(path)
	}
	native := func(path string) string { return nativeFor(f.task.ID, path) }
	var graph struct {
		Nodes []json.RawMessage `json:"nodes"`
		Edges []json.RawMessage `json:"edges"`
	}
	if err := json.Unmarshal(get(native("/exploration/graph?task="+f.task.ID), "GET", 200), &graph); err != nil || len(graph.Nodes) == 0 {
		t.Fatalf("graph native shape: nodes=%d err=%v", len(graph.Nodes), err)
	}
	for _, spec := range []struct{ path, key, marker string }{
		{"exploration/nodes?task=" + f.task.ID, "items", ""},
		{"exploration/intents?task=" + f.task.ID, "", ""},
		{"exploration/frontier?task=" + f.task.ID, "", ""},
		{"exploration/findings?task=" + f.task.ID, "", "本任务发现"},
		{"stats?task=" + f.task.ID, "active_task", ""},
		{"tasks/" + f.task.ID, "id", "owned workflow fixture"},
		{"tasks/" + f.task.ID + "/goals", "goals", "查看现有资料"},
		{"tasks/" + f.task.ID + "/constraints", "constraints", "保持测试资料不变"},
		{"tasks/" + f.task.ID + "/scope", "scope", "shared-"},
		{"tasks/" + f.task.ID + "/coverage", "denominator", ""},
		{"tasks/" + f.task.ID + "/coverage-graph", "nodes", ""},
		{"tasks/" + f.task.ID + "/asset-refs?asset_id=" + fmt.Sprint(f.asset), "intents", ""},
		{"tasks/" + f.task.ID + "/intent-assets", "assets", ""},
		{"assets?task_id=" + f.task.ID + "&limit=5&offset=0", "assets", "本任务示例服务"},
		{"assets/counts?task_id=" + f.task.ID, "", ""},
		{"llm/records/by-model?task=" + f.task.ID, "models", ""},
		{"tasks/" + f.task.ID + "/llm/resolution", "mainagent", ""},
		{"tasks/" + f.task.ID + "/finding-relations", "nodes", ""},
		{"tasks/" + f.task.ID + "/finding-review-status", "enabled", ""},
		{"tasks/" + f.task.ID + "/intercept-rules", "rules", ""},
		{"intercept/task/" + f.task.ID, "items", ""},
		{"report?task=" + f.task.ID, "", "本任务发现"},
		{"tasks/" + f.other.ID + "/reverse/artifacts", "", "示例客户端.bin"},
		{"tasks/" + f.other.ID + "/reverse/conclusions", "", ""},
		{"tasks/" + f.other.ID + "/reverse/runtime", "policy", ""},
		{"tasks/" + f.other.ID + "/reverse/report", "", "逆向分析档案"},
		{"tasks/" + f.task.ID + "/workflow-requests", "", "协助结果样例"},
	} {
		t.Run(strings.Split(spec.path, "?")[0], func(t *testing.T) {
			taskID := f.task.ID
			if strings.HasPrefix(spec.path, "tasks/"+f.other.ID+"/") {
				taskID = f.other.ID
			}
			body := get(nativeFor(taskID, spec.path), "GET", 200)
			if spec.key != "" {
				var shape map[string]json.RawMessage
				if err := json.Unmarshal(body, &shape); err != nil || shape[spec.key] == nil {
					t.Fatalf("response key %q missing or non-object response: %s err=%v", spec.key, body, err)
				}
			}
			if spec.marker != "" && !strings.Contains(string(body), spec.marker) {
				t.Fatalf("missing %q in native response: %s", spec.marker, body)
			}
		})
	}
	statsBody := get(native("/stats?task="+f.task.ID), "GET", 200)
	var scopedStats map[string]json.RawMessage
	if err := json.Unmarshal(statsBody, &scopedStats); err != nil || scopedStats["exploration"] == nil || scopedStats["active_task"] == nil || scopedStats["assets"] != nil || scopedStats["asset_counts"] != nil || scopedStats["traffic"] != nil {
		t.Fatalf("stats must retain task fields without process-wide aggregates: %s err=%v", statsBody, err)
	}
	page := get(native("/exploration/findings?task="+f.task.ID+"&page=1&limit=1"), "GET", 200)
	var findingPage struct {
		Items    []json.RawMessage `json:"items"`
		Total    int               `json:"total"`
		Page     int               `json:"page"`
		PageSize int               `json:"page_size"`
	}
	if err := json.Unmarshal(page, &findingPage); err != nil || findingPage.Total != 2 || len(findingPage.Items) != 1 || findingPage.Page != 1 || findingPage.PageSize != 1 {
		t.Fatalf("task finding page shape: %+v err=%v body=%s", findingPage, err, page)
	}
	if raw := get(native(fmt.Sprintf("exploration/findings/%d/retests", f.finding)), "GET", 200); !strings.Contains(string(raw), "复测结果样例") {
		t.Fatalf("retests native shape: %s", raw)
	}
	get(native(fmt.Sprintf("exploration/findings/%d/retests", f.foreign)), "GET", 404)
	get(native(fmt.Sprintf("exploration/findings/%d/lineage", f.finding)), "GET", 200)
	get(native(fmt.Sprintf("exploration/findings/%d/traffic", f.finding)), "GET", 200)
	get(native("tasks/"+f.other.ID+"/coverage"), "GET", 403)
	get(native("tasks/"+f.other.ID+"/llm/resolution"), "GET", 403)
	get(native("exploration/graph?task="+f.other.ID), "GET", 403)
	get(native("tasks/"+f.task.ID+"/llm/resolution?task="+f.other.ID), "GET", 403)
	resolution := get(native("tasks/"+f.task.ID+"/llm/resolution"), "GET", 200)
	if strings.Contains(strings.ToLower(string(resolution)), "api_key") || strings.Contains(strings.ToLower(string(resolution)), "apikey") {
		t.Fatalf("LLM resolution exposed credentials: %s", resolution)
	}
	get(native("exploration/graph?task="+f.task.ID+"&task="+f.other.ID), "GET", 403)
	get(native("exploration/graph?task_id="+f.task.ID+"&task_id="+f.other.ID), "GET", 403)
	get(native("exploration/findings/1?context_task="+f.other.ID), "GET", 403)
	get(native("exploration/findings/1?context_task="+f.task.ID+"&context_task="+f.other.ID), "GET", 403)
	get(native("/exploration/graph")+"&path=exploration/graph", "GET", 400)
	get(native("assets?task_id="+f.other.ID), "GET", 403)
	for _, bad := range []string{"//exploration/graph", "https://example.test/exploration/graph", "exploration/../tasks", "exploration/./graph", "exploration\\graph", "settings"} {
		want := 400
		if bad == "settings" {
			want = 404
		}
		get(native(bad), "GET", want)
	}
	get(native("tasks/"+f.task.ID+"/control"), "GET", 404)
	get(native("exploration/graph"), "POST", 405)

	// Direct-source findings are visible only while the explicit relation exists.
	tid, oid := mustTaskID(t, f.task.ID), mustTaskID(t, f.other.ID)
	if _, err := f.s.m.pg.Exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, tid, oid); err != nil {
		t.Fatal(err)
	}
	get(native(fmt.Sprintf("exploration/findings/%d", f.foreign)), "GET", 200)
	if _, err := f.s.m.pg.Exec(`DELETE FROM task_relations WHERE task_id=$1 AND source_task_id=$2`, tid, oid); err != nil {
		t.Fatal(err)
	}
	get(native(fmt.Sprintf("exploration/findings/%d", f.foreign)), "GET", 404)

	// Approval detail keeps the original DTO while omitting tool input and raw execution output.
	for _, suffix := range []string{"", "?page=1&size=10"} {
		raw := get(native("/intercept/task/"+f.task.ID+suffix), "GET", 200)
		var rows struct {
			Items []db.InterceptApprovalRow `json:"items"`
		}
		if err := json.Unmarshal(raw, &rows); err != nil || len(rows.Items) == 0 {
			t.Fatalf("approval list missing: %s err=%v", raw, err)
		}
		for _, row := range rows.Items {
			if len(row.ToolInput) > 0 && string(row.ToolInput) != "null" {
				t.Fatal("shared approval list exposed raw tool input")
			}
		}
	}
	var approvalID int64
	if err := f.s.m.pg.QueryRow(`SELECT id FROM intercept_pending WHERE task_id=$1 ORDER BY id DESC LIMIT 1`, f.task.ID).Scan(&approvalID); err != nil {
		t.Fatal(err)
	}
	detail := get(native(fmt.Sprintf("intercept/history/%d", approvalID)), "GET", 200)
	var detailDTO map[string]any
	if err := json.Unmarshal(detail, &detailDTO); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(detail), "DO_NOT_SHARE_TOOL_TRACE") || detailDTO["tool_input"] != nil {
		t.Fatalf("approval detail leaked raw input: %s", detail)
	}
	if audit, ok := detailDTO["audit"].(map[string]any); ok && (audit["model_input"] != nil || audit["output"] != nil && audit["output"] != "") {
		t.Fatalf("approval detail leaked execution activity: %s", detail)
	}

	// The reverse material download is scoped to the current reverse task.
	artifactDir := filepath.Join(f.s.m.dir, "tasks", f.other.ID, "reverse", "artifacts")
	if err := os.MkdirAll(artifactDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "safe.bin"), []byte("fixture artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := f.s.m.pg.AddReverseArtifact(oid, db.ReverseArtifact{Name: "safe.bin", Format: "native", SizeBytes: 15, SHA256: strings.Repeat("b", 64), Version: "v2", Path: filepath.Join("tasks", f.other.ID, "reverse", "artifacts", "safe.bin"), Source: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if body := get(nativeFor(f.other.ID, fmt.Sprintf("tasks/%s/reverse/artifacts/%d/download", f.other.ID, a.ID)), "GET", 200); string(body) != "fixture artifact" {
		t.Fatalf("artifact download: %s", body)
	}
	get(native(fmt.Sprintf("tasks/%s/reverse/artifacts/%d/download", f.task.ID, a.ID)), "GET", 404)

	if _, err := f.s.m.pg.Exec(`DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3 AND permission='read'`, f.team, tid, f.member); err != nil {
		t.Fatal(err)
	}
	get(native("/exploration/graph"), "GET", 403)
}
