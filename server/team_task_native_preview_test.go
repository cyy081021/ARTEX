package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	rootNode, err := f.task.Store.AddNode(db.KindGoal, map[string]any{"text": "合成服务验证与独立复核"}, 1, "open", "fixture", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 24; i++ {
		intent, e := f.task.Store.AddNode(db.KindIntent, map[string]any{"title": fmt.Sprintf("服务 %02d · 验证已有线索", i+1), "text": "依据测试材料核对行为与证据"}, 1, "done", "fixture", nil)
		if e != nil {
			t.Fatal(e)
		}
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
		listener, e := net.Listen("tcp", address)
		if e != nil {
			t.Fatal(e)
		}
		server := &http.Server{Handler: app}
		t.Cleanup(func() { _ = server.Close() })
		go func() { _ = server.Serve(listener) }()
	}
	serve("127.0.0.1:8896", f.token, fmt.Sprintf("/function/team/task/?team=%d&id=%s&tab=graph", f.team, f.task.ID), f.s.TeamHandler())
	serve("127.0.0.1:8897", ownerToken, "/function/tasks/detail/?id="+f.task.ID, f.s.Handler())
	meta, _ := json.Marshal(map[string]any{"url": "http://localhost:8896/fixture", "owner_url": "http://localhost:8897/fixture", "team": f.team, "task": f.task.ID, "reverse": f.other.ID, "finding": f.finding, "member": f.member})
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
