package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/golang-jwt/jwt/v5"
)

// Opt-in comparison: the exact same synthetic task is opened through the owner
// and member listeners. No model or tool runner is configured by this fixture.
func TestTeamTaskNativeBrowserPreview(t *testing.T) {
	output := os.Getenv("ARTEX_MEMBER_CONTENT_PREVIEW_DIR")
	if output == "" {
		t.Skip("opt-in native task UI fixture")
	}
	if !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=member_content_preview ") {
		t.Fatal("isolated preview database required")
	}
	f := newTeamContentFixture(t)
	ctx := context.Background()
	operator, err := f.s.m.pg.CreateTeamMember(ctx, f.team, "session-operator", "unused")
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range []string{"read", "execute"} {
		if err = f.s.m.pg.AttachTeamTask(ctx, f.team, mustTaskID(t, f.task.ID), operator.ID, permission); err != nil {
			t.Fatal(err)
		}
	}
	operatorToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", f.team, operator.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(f.s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.s.m.pg.SetStatus(mustTaskID(t, f.task.ID), "running"); err != nil {
		t.Fatal(err)
	}
	if err = f.s.m.pg.SetPaused(mustTaskID(t, f.task.ID), false); err != nil {
		t.Fatal(err)
	}
	f.task.updateLifecycle(func(v *taskLifecycleState) { v.Status = "running"; v.Paused = false })
	iid, err := f.task.Store.AddWorkIntent(ctx, "隔离 Worker · 消息引导验收", 1, nil, nil, db.WorkContract{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.task.Store.SetNodeState(iid, "running"); err != nil {
		t.Fatal(err)
	}
	control := agent.NewLiveControl(nil)
	f.s.engine.workMu.Lock()
	f.s.engine.work[iid] = &workExecution{control: control}
	f.s.engine.workMu.Unlock()
	t.Cleanup(func() { control.Close() })
	appendMessage := func(a db.Activity) {
		t.Helper()
		if _, err := f.task.Store.AppendActivity(a); err != nil {
			t.Fatal(err)
		}
	}
	markdown := "## 本轮核对\n\n**格式与原会话一致**，保留 `evidence_version`。\n\n- 第一项：标题、加粗与列表\n- 第二项：代码块和表格\n\n```json\n{\"status\": \"verified\", \"source\": \"fixture\"}\n```\n\n| 项目 | 结果 |\n| --- | --- |\n| Markdown | 已渲染 |\n| 成员会话 | 使用原组件 |\n\n> 所有内容均为隔离环境中的合成测试材料。"
	for _, worker := range []string{"mainagent", "planner"} {
		for i := 0; i < 105; i++ {
			appendMessage(db.Activity{Worker: worker, Kind: "text", Summary: fmt.Sprintf("合成历史消息 %03d", i), Detail: fmt.Sprintf("合成历史消息 %03d", i)})
		}
		appendMessage(db.Activity{Worker: worker, Kind: "user", Summary: "请核对本轮结果。", Detail: "请核对本轮结果。"})
		input, cache, output := 23000, 18000, 1400
		appendMessage(db.Activity{Worker: worker, Kind: "result", Summary: markdown, Detail: markdown, InputTokens: &input, CacheReadTokens: &cache, OutputTokens: &output})
	}
	appendMessage(db.Activity{Worker: "system", Kind: "llm_failover", Summary: "合成系统审计：模型切换完成。", Detail: "PRIVATE_FIXTURE_DETAIL"})
	appendMessage(db.Activity{NodeID: &iid, Worker: "fixture", Kind: "result", Summary: markdown, Detail: markdown})
	rootNode, err := f.task.Store.AddNode(db.KindGoal, map[string]any{"text": "合成服务验证与独立复核"}, 1, "open", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 24; i++ {
		intent, e := f.task.Store.AddNode(db.KindIntent, map[string]any{"title": fmt.Sprintf("服务 %02d · 验证已有线索", i+1), "text": "依据测试材料核对行为与证据"}, 1, "done", "fixture", nil)
		if e != nil {
			t.Fatal(e)
		}
		appendMessage(db.Activity{NodeID: &intent, Worker: "fixture", Kind: "result", Summary: markdown, Detail: markdown})
		if e = f.task.Store.Link(rootNode, "spawns", intent); e != nil {
			t.Fatal(e)
		}
		for j := 0; j < 12; j++ {
			fact, e := f.task.Store.AddNode(db.KindFact, map[string]any{"text": fmt.Sprintf("服务 %02d · 观察 %02d", i+1, j+1), "summary": "合成验证结果，保留原始观察与边界"}, 1, "confirmed", "fixture", nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = f.task.Store.Link(intent, "yields", fact); e != nil {
				t.Fatal(e)
			}
		}
	}
	root, err := filepath.Abs("../web/out")
	if err != nil {
		t.Fatal(err)
	}
	ownerToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: "ARTEX", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(f.s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(address, token, destination string, handler http.Handler) {
		app := http.NewServeMux()
		app.Handle("/api/", handler)
		app.Handle("/", http.FileServer(http.Dir(root)))
		app.HandleFunc("GET /fixture", func(w http.ResponseWriter, r *http.Request) {
			raw, _ := json.Marshal(token)
			fmt.Fprintf(w, `<!doctype html><script>localStorage.setItem("artex_token",%s);location.href=%q</script>`, raw, destination)
		})
		app.HandleFunc("GET /fixture/operator", func(w http.ResponseWriter, r *http.Request) {
			raw, _ := json.Marshal(operatorToken)
			fmt.Fprintf(w, `<!doctype html><script>localStorage.setItem("artex_token",%s);location.href=%q</script>`, raw, fmt.Sprintf("/function/team/task/?team=%d&id=%s&tab=sessions", f.team, f.task.ID))
		})
		listener, e := net.Listen("tcp", address)
		if e != nil {
			t.Fatal(e)
		}
		server := &http.Server{Handler: app}
		t.Cleanup(func() { _ = server.Close() })
		go func() { _ = server.Serve(listener) }()
	}
	serve("127.0.0.1:8896", f.token, fmt.Sprintf("/function/team/task/?team=%d&id=%s&tab=sessions", f.team, f.task.ID), f.s.TeamHandler())
	serve("127.0.0.1:8897", ownerToken, "/function/tasks/detail/?id="+f.task.ID, f.s.Handler())
	meta, _ := json.Marshal(map[string]any{"url": "http://localhost:8896/fixture", "operator_url": "http://localhost:8896/fixture/operator", "owner_url": "http://localhost:8897/fixture", "team": f.team, "task": f.task.ID, "reverse": f.other.ID, "finding": f.finding, "member": f.member})
	if err = os.WriteFile(filepath.Join(output, "preview.json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("native owner/member task comparison ready")
	deadline := time.Now().Add(19 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(output, "preview.stop")); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
