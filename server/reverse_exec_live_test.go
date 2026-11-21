package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// TestSandboxExecLive exercises the real execution path on Linux: a whitelisted
// binary actually runs, its evidence file lands in the task directory, and the
// shell/escape attempts are refused without writing anything. It only runs where
// the whitelisted tools exist, so Windows hosts skip it.
func TestSandboxExecLive(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("sandbox_exec needs a Linux host with binutils")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello artex\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	task := &db.Task{ID: 7}
	info := agent.RunInfo{TaskID: 7, IntentID: 42}
	tool := reverseExecTool(task, info, dir, "reverse_static")

	call := func(argv []string) {
		raw, _ := json.Marshal(map[string]any{"argv": argv, "purpose": "live verification"})
		if _, err := tool.Call(context.Background(), raw, nil); err != nil {
			t.Fatalf("call %v returned error: %v", argv, err)
		}
	}
	countExec := func() int {
		entries, err := os.ReadDir(filepath.Join(dir, "exec"))
		if err != nil {
			return 0
		}
		return len(entries)
	}

	call([]string{"file", "hello.txt"})
	if got := countExec(); got != 1 {
		t.Fatalf("expected exactly one evidence file, got %d", got)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "exec"))
	body, err := os.ReadFile(filepath.Join(dir, "exec", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatalf("evidence is not JSON: %v", err)
	}
	if record["operation"] != "sandbox_exec" || record["authority"] != "static-inspection" {
		t.Fatalf("evidence lost its authority labels: %v", record)
	}
	if out, _ := record["output_tail"].(string); !strings.Contains(out, "ASCII text") {
		t.Fatalf("file(1) output missing from evidence: %q", out)
	}

	call([]string{"bash", "-c", "echo pwned"})
	call([]string{"/usr/bin/objdump", "-d", "hello.txt"})
	if got := countExec(); got != 1 {
		t.Fatalf("rejected commands must not write evidence, got %d files", got)
	}

	reviewer := reverseExecTool(task, info, dir, "reverse_reviewer")
	rawReviewer, _ := json.Marshal(map[string]any{"argv": []string{"python3", "-c", "print(1)"}})
	if _, err := reviewer.Call(context.Background(), rawReviewer, nil); err != nil {
		t.Fatalf("reviewer call returned error: %v", err)
	}
	if got := countExec(); got != 1 {
		t.Fatalf("reviewer must not be able to run interpreters, got %d files", got)
	}
}
