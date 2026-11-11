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
)

// Opt-in UI acceptance. Synthetic data and no model/tool executor are started.
func TestBranchSetupBrowserPreview(t *testing.T) {
	out := os.Getenv("ARTEX_BRANCH_SETUP_PREVIEW_DIR")
	if out == "" || !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=branch_autosetup_preview") {
		t.Skip("requires dedicated preview database and explicit opt-in")
	}
	f := newBranchSetupFixture(t)
	if _, err := f.s.m.pg.Exec(`UPDATE tasks SET name='协作流程隔离验收',goal='核对示例应用的行为与材料，按设备能力拆分工作并汇总结果' WHERE id=$1`, f.task); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(filepath.Join("..", "web", "out"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", f.s.Handler())
	mux.Handle("/", http.FileServer(http.Dir(root)))
	mux.HandleFunc("GET /fixture", func(w http.ResponseWriter, r *http.Request) {
		token, _ := json.Marshal(f.token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, `<html><title>ARTEX 自动协作隔离验收</title><script>localStorage.setItem("artex_token",%s);location.href="/function/team/?team=%d";</script></html>`, token, f.team)
	})
	l, err := net.Listen("tcp", "127.0.0.1:8895")
	if err != nil {
		t.Fatal(err)
	}
	host := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	defer host.Close()
	go host.Serve(l)
	raw, _ := json.MarshalIndent(map[string]any{"url": "http://127.0.0.1:8895/fixture", "team": f.team, "task": f.task, "device": f.device}, "", "  ")
	if err = os.WriteFile(filepath.Join(out, "preview.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("isolated automatic collaboration preview ready at localhost:8895")
	for start := time.Now(); time.Since(start) < 19*time.Minute; {
		if _, e := os.Stat(filepath.Join(out, "preview.stop")); e == nil {
			return
		}
		if _, e := f.s.m.pg.Exec(`UPDATE team_devices SET last_seen_at=now() WHERE id=$1`, f.device); e != nil {
			t.Fatal(e)
		}
		time.Sleep(time.Second)
	}
}
