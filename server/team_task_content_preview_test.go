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

func TestTeamTaskContentBrowserPreview(t *testing.T) {
	output := os.Getenv("ARTEX_MEMBER_CONTENT_PREVIEW_DIR")
	if output == "" {
		t.Skip("opt-in member content UI fixture")
	}
	if !strings.Contains(os.Getenv("ARTEX_PG_DSN"), "dbname=member_content_preview ") {
		t.Fatal("isolated preview database required")
	}
	f := newTeamContentFixture(t)
	root, err := filepath.Abs("../web/out")
	if err != nil {
		t.Fatal(err)
	}
	app := http.NewServeMux()
	app.Handle("/api/", f.s.TeamHandler())
	app.Handle("/", http.FileServer(http.Dir(root)))
	app.HandleFunc("GET /fixture", func(w http.ResponseWriter, r *http.Request) {
		token, _ := json.Marshal(f.token)
		dest := fmt.Sprintf("/function/team/task/?team=%d&id=%s", f.team, f.task.ID)
		fmt.Fprintf(w, `<!doctype html><script>localStorage.setItem("artex_token",%s);location.href=%q</script>`, token, dest)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:8896")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: app}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	meta, _ := json.Marshal(map[string]any{"url": "http://localhost:8896/fixture", "team": f.team, "task": f.task.ID, "reverse": f.other.ID, "finding": f.finding, "member": f.member})
	if err = os.WriteFile(filepath.Join(output, "preview.json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("read-only member content preview ready on localhost:8896")
	deadline := time.Now().Add(19 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(output, "preview.stop")); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
