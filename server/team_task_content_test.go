package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

type teamContentFixture struct {
	s                                                   *Server
	task, other                                         *Task
	team, member, finding, foreign, asset, foreignAsset int64
	token, base                                         string
}

func newTeamContentFixture(t *testing.T) *teamContentFixture {
	t.Helper()
	s, task, other := workflowFixture(t)
	pg := s.m.pg
	ctx := context.Background()
	f := &teamContentFixture{s: s, task: task, other: other}
	tid, oid := mustTaskID(t, task.ID), mustTaskID(t, other.ID)
	team, err := pg.CreateTeam(ctx, "成员完整任务资料验收")
	if err != nil {
		t.Fatal(err)
	}
	f.team = team.ID
	t.Cleanup(func() {
		_, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID)
		_, _ = pg.Exec(`DELETE FROM findings WHERE task_id IN ($1,$2)`, tid, oid)
		_, _ = pg.Exec(`DELETE FROM assets WHERE $1=ANY(task_ids) OR $2=ANY(task_ids)`, tid, oid)
	})
	member, err := pg.CreateTeamMember(ctx, team.ID, "content-reader", "unused")
	if err != nil {
		t.Fatal(err)
	}
	f.member = member.ID
	for _, id := range []int64{tid, oid} {
		if err = pg.AttachTeamTask(ctx, team.ID, id, member.ID, "read"); err != nil {
			t.Fatal(err)
		}
	}
	f.token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, member.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	f.base = fmt.Sprintf("/api/teams/%d/tasks/%d/view/", team.ID, tid)
	_, err = pg.Exec(`UPDATE tasks SET name=$2 WHERE id=$1`, tid, "共享资料示例任务")
	if err != nil {
		t.Fatal(err)
	}
	_, err = task.Store.AddGoal(map[string]any{"text": "查看现有资料与验证结论"}, "human")
	if err != nil {
		t.Fatal(err)
	}
	_, err = task.Store.AddConstraint("rule", "保持测试资料不变", "human")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pg.Exec(`INSERT INTO task_scope(task_id,kind,domain,source) VALUES($1,'root_domain',$2,'agent')`, tid, fmt.Sprintf("shared-%d.invalid", tid))
	if err != nil {
		t.Fatal(err)
	}
	f.asset, err = s.m.Assets().UpsertHTTPService(db.UpsertHTTPServiceReq{URL: fmt.Sprintf("https://shared-%d.invalid/", tid), TaskID: tid, PageTitle: "本任务示例服务"})
	if err != nil {
		t.Fatal(err)
	}
	f.foreignAsset, err = s.m.Assets().UpsertIP(db.UpsertIPReq{IP: "192.0.2.240", TaskID: oid})
	if err != nil {
		t.Fatal(err)
	}
	makeFinding := func(task *Task, name string) int64 {
		node, e := task.Store.AddNode(db.KindFinding, map[string]any{"name": name, "vulnclass": "fixture", "severity": "medium", "summary": name + "摘要", "evidence": map[string]any{"poc": "仅合成测试材料"}}, 1, "confirmed", "fixture", nil)
		if e != nil {
			t.Fatal(e)
		}
		id, e := pg.AddFinding(mustTaskID(t, task.ID), node, "fixture", name, "medium", name+"摘要", "合成证据", "fixture", nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pg.SetFindingReportByNodeID(node, "# "+name+"详细报告\n\n复现和修复建议，仅用于页面验收。"); e != nil {
			t.Fatal(e)
		}
		return id
	}
	f.finding = makeFinding(task, "本任务发现")
	second := makeFinding(task, "第二条发现")
	f.foreign = makeFinding(other, "不相关任务的发现")
	if _, err = pg.SaveFindingRelation(ctx, tid, db.FindingRelation{Source: f.finding, Target: second, Kind: "supports", Status: "verified", Rationale: "合成关联依据", Evidence: "两份自有合成材料的结果一致"}); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO finding_retests(finding_id,status,verdict,notes,snapshot,summary,evidence) VALUES($1,'completed','reproduced','合成复测说明','{}'::jsonb,'复测结果样例','合成复测证据')`, f.finding); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.CreateInterceptPending(0, 0, task.ID, "fixture-worker", "fixture_tool", []byte(`{"private_tool_input":"DO_NOT_SHARE_TOOL_TRACE"}`), "需要人工判断的示例理由"); err != nil {
		t.Fatal(err)
	}
	if _, err = pg.Exec(`INSERT INTO workflow_requests(request_key,source_task_id,target_task_id,question,acceptance,input_snapshot,status,budget_seconds,depth,expires_at,result) VALUES('member-content-fixture',$1,$2,'分析已有材料','["返回证据"]'::jsonb,'{}'::jsonb,'completed',60,1,now()+interval '1 hour','{"summary":"协助结果样例"}'::jsonb)`, tid, oid); err != nil {
		// Keep the fixture SQL explicit and independent from model dispatch.
		t.Fatal(err)
	}
	if _, err = pg.AddReverseArtifact(oid, db.ReverseArtifact{Name: "示例客户端.bin", Format: "native", SizeBytes: 4, SHA256: strings.Repeat("a", 64), Version: "v1", Path: "PRIVATE_EXECUTOR_PATH/client.bin", Source: "fixture"}); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTeamTaskContentReadSectionsScopeAndPagination(t *testing.T) {
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
		raw, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, raw)
		}
		if want == 200 && resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("member content must not be cached after revocation")
		}
		return raw
	}
	markers := map[string]string{"overview": "保持测试资料不变", "graph": "本任务发现", "broadcast": "本任务发现", "findings": "本任务发现", "finding-relations": "合成关联依据", "retests": "复测结果样例", "assets": "本任务示例服务", "coverage": "shared-", "intercept": "示例理由", "report": "本任务发现", "workflow-requests": "协助结果样例"}
	for section, marker := range markers {
		t.Run(section, func(t *testing.T) {
			raw := get(f.base+section, "GET", 200)
			if !strings.Contains(string(raw), marker) {
				t.Fatalf("missing content %q: %s", marker, raw)
			}
			if strings.Contains(string(raw), "DO_NOT_SHARE_TOOL_TRACE") || strings.Contains(string(raw), "不相关任务的发现") {
				t.Fatalf("unrelated content returned: %s", raw)
			}
		})
	}
	page1 := get(f.base+"findings?size=1&page=1", "GET", 200)
	page2 := get(f.base+"findings?size=1&page=2", "GET", 200)
	var a, b teamTaskContent
	_ = json.Unmarshal(page1, &a)
	_ = json.Unmarshal(page2, &b)
	if a.Total != 2 || len(a.Rows) != 1 || !a.HasMore || len(b.Rows) != 1 || a.Rows[0].ID == b.Rows[0].ID || b.HasMore {
		t.Fatalf("pagination mismatch: %+v %+v", a, b)
	}
	raw := get(f.base+fmt.Sprintf("findings/%d", f.finding), "GET", 200)
	if !strings.Contains(string(raw), "详细报告") || !strings.Contains(string(raw), "合成复测证据") {
		t.Fatalf("incomplete finding detail: %s", raw)
	}
	get(f.base+fmt.Sprintf("findings/%d", f.foreign), "GET", 404)
	get(f.base+fmt.Sprintf("assets/%d", f.foreignAsset), "GET", 404)
	get(f.base+fmt.Sprintf("assets/%d", f.asset), "GET", 200)
	get(f.base+"findings?size=1000", "GET", 400)
	get(f.base+"findings?page=9223372036854775807", "GET", 400)
	get(f.base+"findings", "POST", 405)
	get("/api/tasks/"+f.task.ID, "GET", 403)
	otherBase := fmt.Sprintf("/api/teams/%d/tasks/%s/view/", f.team, f.other.ID)
	raw = get(otherBase+"reverse", "GET", 200)
	if !strings.Contains(string(raw), "示例客户端.bin") || strings.Contains(string(raw), "PRIVATE_EXECUTOR_PATH") {
		t.Fatalf("reverse projection: %s", raw)
	}
	get(otherBase+"report", "GET", 200)
	tid, oid := mustTaskID(t, f.task.ID), mustTaskID(t, f.other.ID)
	if _, err := f.s.m.pg.Exec(`INSERT INTO task_relations(task_id,source_task_id) VALUES($1,$2)`, tid, oid); err != nil {
		t.Fatal(err)
	}
	get(f.base+fmt.Sprintf("findings/%d", f.foreign), "GET", 200)
	if _, err := f.s.m.pg.Exec(`DELETE FROM task_relations WHERE task_id=$1 AND source_task_id=$2`, tid, oid); err != nil {
		t.Fatal(err)
	}
	get(f.base+fmt.Sprintf("findings/%d", f.foreign), "GET", 404)
	if _, err := f.s.m.pg.Exec(`DELETE FROM team_task_permissions WHERE team_id=$1 AND task_id=$2 AND member_id=$3 AND permission='read'`, f.team, tid, f.member); err != nil {
		t.Fatal(err)
	}
	for section := range markers {
		get(f.base+section, "GET", 403)
	}
	get(f.base+fmt.Sprintf("findings/%d", f.finding), "GET", 403)
}

func TestTeamTaskReportCountsOnlyCurrentTaskAssets(t *testing.T) {
	f := newTeamContentFixture(t)
	before, err := f.s.taskReportMarkdown(f.task)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.m.Assets().UpsertIP(db.UpsertIPReq{IP: "192.0.2.241", TaskID: mustTaskID(t, f.other.ID)})
	if err != nil {
		t.Fatal(err)
	}
	after, err := f.s.taskReportMarkdown(f.task)
	if err != nil {
		t.Fatal(err)
	}
	assetLine := func(md string) string {
		for _, line := range strings.Split(md, "\n") {
			if strings.HasPrefix(line, "- 资产：") {
				return line
			}
		}
		return ""
	}
	if assetLine(before) == "" || assetLine(before) != assetLine(after) || strings.Contains(assetLine(after), "ip ") {
		t.Fatalf("foreign asset count affected report: %q -> %q", assetLine(before), assetLine(after))
	}
}
