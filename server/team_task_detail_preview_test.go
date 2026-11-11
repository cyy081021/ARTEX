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

// Opt-in real HTTP/UI fixture. Work is synthetic; no model or tool is invoked.
func TestTeamTaskDetailBrowserPreview(t *testing.T) {
	output := os.Getenv("ARTEX_MEMBER_DETAIL_PREVIEW_DIR")
	if output == "" {
		t.Skip("manual member detail preview is opt-in")
	}
	if !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=guidance_preview ") {
		t.Fatal("preview requires the isolated guidance_preview database")
	}
	root, err := filepath.Abs("../web/out")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "function/team/task/index.html")); err != nil {
		t.Fatal(err)
	}
	s, task, _ := workflowFixture(t)
	ctx := context.Background()
	pg := s.m.pg
	tid := mustTaskID(t, task.ID)
	team, err := pg.CreateTeam(ctx, "成员任务详情隔离验收")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pg.Exec(`DELETE FROM teams WHERE id=$1`, team.ID) })
	tokens := map[string]string{}
	for _, role := range []string{"operator", "reader"} {
		m, e := pg.CreateTeamMember(ctx, team.ID, role, "unused")
		if e != nil {
			t.Fatal(e)
		}
		permissions := []string{"read"}
		if role == "operator" {
			permissions = append(permissions, "execute")
		}
		for _, permission := range permissions {
			if e = pg.AttachTeamTask(ctx, team.ID, tid, m.ID, permission); e != nil {
				t.Fatal(e)
			}
		}
		tokens[role], e = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{Subject: fmt.Sprintf("team:%d:%d", team.ID, m.ID), ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}).SignedString(s.jwtKey)
		if e != nil {
			t.Fatal(e)
		}
	}
	if err = pg.SetStatus(tid, "running"); err != nil {
		t.Fatal(err)
	}
	if err = pg.SetPaused(tid, false); err != nil {
		t.Fatal(err)
	}
	task.updateLifecycle(func(v *taskLifecycleState) { v.Status = "running"; v.Paused = false })
	for _, state := range []string{"running", "open", "done"} {
		iid, e := task.Store.AddWorkIntent(ctx, "隔离 Worker · "+state, 1, nil, nil, db.WorkContract{})
		if e != nil {
			t.Fatal(e)
		}
		if e = task.Store.SetNodeState(iid, state); e != nil {
			t.Fatal(e)
		}
		if state == "running" {
			control := agent.NewLiveControl(nil)
			s.engine.workMu.Lock()
			s.engine.work[iid] = &workExecution{control: control}
			s.engine.workMu.Unlock()
			t.Cleanup(func() { control.Close() })
		}
		if _, e = task.Store.AppendActivity(db.Activity{NodeID: &iid, Worker: "fixture", Kind: "text", Summary: "合成会话消息：只用于验证成员视图与消息发送，不运行真实目标。"}); e != nil {
			t.Fatal(e)
		}
	}
	if _, err = task.Store.AppendActivity(db.Activity{Worker: "mainagent", Kind: "text", Summary: "主 Agent 合成历史消息。"}); err != nil {
		t.Fatal(err)
	}
	assets := http.NewServeMux()
	assets.Handle("/api/", s.Handler())
	assets.Handle("/", http.FileServer(http.Dir(root)))
	handler := http.NewServeMux()
	handler.Handle("/", s.teamOnly(assets))
	handler.HandleFunc("GET /fixture/{role}", func(w http.ResponseWriter, r *http.Request) {
		token, ok := tokens[r.PathValue("role")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		encoded, _ := json.Marshal(token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<html><title>成员详情隔离验收</title><script>localStorage.setItem("artex_token",%s);location.href="/function/team/?team=%d";</script></html>`, encoded, team.ID)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8897")
	if err != nil {
		t.Fatal(err)
	}
	host := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	defer host.Close()
	go host.Serve(listener)
	info, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:8897/fixture/operator", "reader_url": "http://127.0.0.1:8897/fixture/reader", "team": team.ID, "task": tid})
	if err = os.WriteFile(filepath.Join(output, "preview.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated member detail preview ready on 127.0.0.1:8897")
	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(filepath.Join(output, "preview.stop")); e == nil {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}
