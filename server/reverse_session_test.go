package server

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestReverseSessionRunnerFixture(t *testing.T) {
	mode := os.Getenv("ARTEX_SESSION_TEST_HELPER")
	if mode == "" {
		return
	}
	hash := sha256.Sum256([]byte("fixture-script"))
	observation := map[string]any{"platform": "linux", "artifact_sha256": "fixture-hash", "script_sha256": hex.EncodeToString(hash[:]), "messages": []any{}, "cleanup": map[string]any{"script_unloaded": true, "session_detached": true, "owned_process_terminated": mode != "unclean", "staging_removed": true}, "errors": []any{}}
	emit := func(id, kind string) {
		_ = json.NewEncoder(os.Stdout).Encode(reverseSessionFrame{RequestID: id, Kind: kind, Observation: observation})
	}
	scan := bufio.NewScanner(os.Stdin)
	for scan.Scan() {
		var req map[string]any
		_ = json.Unmarshal(scan.Bytes(), &req)
		if req["cancel"] == true {
			observation["cancelled"] = true
			observation["reason"] = "cancelled"
			emit("final", "final")
			os.Exit(0)
		}
		id, _ := req["request_id"].(string)
		if mode == "malformed" {
			_, _ = os.Stdout.WriteString("not json\n")
			os.Exit(1)
		}
		if req["action"] == "stop" {
			observation["reason"] = "stop"
			emit(id, "final")
			os.Exit(0)
		}
		if mode == "detached" {
			observation["reason"] = "detached"
			emit(id, "final")
			os.Exit(0)
		}
		if req["action"] == "wait" {
			continue
		}
		observation["messages"] = []any{map[string]any{"pid": os.Getpid(), "step_id": id, "payload": "fixture value 16"}}
		emit(id, "step")
	}
	observation["cancelled"] = true
	observation["reason"] = "cancelled"
	emit("final", "final")
	os.Exit(0)
}

func reverseSessionFixture(t *testing.T, mode string) (*reverseSession, chan string) {
	t.Helper()
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReverseSessionRunnerFixture$")
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ARTEX_PG_DSN=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	// The child is a pipe fixture, not a second DB suite. Avoid waiting on the
	// parent's PostgreSQL TestMain advisory lock.
	cmd.Env = append(cmd.Env, "ARTEX_SESSION_TEST_HELPER="+mode, "ARTEX_PG_DSN=postgres://127.0.0.1:1/fixture?connect_timeout=1&sslmode=disable")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan string, 1)
	s := &reverseSession{id: "fixture-session", runID: 1, profile: reverseRuntimeProfile{Platform: "linux"}, artifact: &db.ReverseArtifact{Name: "fixture", SHA256: "fixture-hash"}, script: "fixture-script", dir: dir, workDir: dir, command: cmd, in: in, done: make(chan struct{}), pending: map[string]chan map[string]any{}, finish: func(status, path, msg string) error {
		finished <- status
		if mode == "finishfail" {
			return errors.New("fixture database failure")
		}
		return nil
	}, release: func() {}}
	go s.read(out)
	t.Cleanup(s.close)
	return s, finished
}

func TestReverseSessionPersistsStepsAndFinalCleanup(t *testing.T) {
	s, finished := reverseSessionFixture(t, "normal")
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var paths []string
	for i := 0; i < 2; i++ {
		result, err := s.request(ctx, map[string]any{"action": "read"})
		if err != nil || result["status"] != "running" {
			t.Fatalf("step=%v err=%v", result, err)
		}
		path := reverseSessionString(result["result_path"])
		paths = append(paths, path)
		raw, err := os.ReadFile(filepath.Join(s.workDir, path))
		if err != nil || !strings.Contains(string(raw), "fixture value 16") {
			t.Fatalf("evidence %s %v", raw, err)
		}
	}
	if paths[0] == paths[1] {
		t.Fatal("steps overwrote evidence")
	}
	result, err := s.request(ctx, map[string]any{"action": "stop"})
	if err != nil || result["status"] != "completed" || <-finished != "completed" {
		t.Fatalf("final=%v %v", result, err)
	}
	result, err = s.request(ctx, map[string]any{"action": "android_tap", "x": 1, "y": 1})
	if err != nil || result["is_error"] != true || result["command_completed"] != false {
		t.Fatalf("closed session pretended to execute: %v %v", result, err)
	}
}

func TestReverseSessionCancellationAndFailures(t *testing.T) {
	for _, mode := range []string{"normal", "unclean", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			s, finished := reverseSessionFixture(t, mode)
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Millisecond)
			defer cancel()
			_, _ = s.request(ctx, map[string]any{"action": "wait"})
			select {
			case status := <-finished:
				want := "failed"
				if mode == "normal" {
					want = "cancelled"
				}
				if status != want {
					t.Fatalf("status=%s want=%s", status, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runner did not finish")
			}
			s.mu.Lock()
			result := s.last
			s.mu.Unlock()
			if reverseSessionString(result["result_path"]) == "" {
				t.Fatal("terminal evidence missing")
			}
		})
	}
}

func TestReverseSessionDetachedAndFinishFailureStayFailed(t *testing.T) {
	t.Run("detached clean runner is failed", func(t *testing.T) {
		s, finished := reverseSessionFixture(t, "detached")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		result, err := s.request(ctx, map[string]any{"action": "read"})
		if err != nil || result["status"] != "failed" || result["is_error"] != true || <-finished != "failed" {
			t.Fatalf("detached final=%v err=%v", result, err)
		}
		raw, err := os.ReadFile(filepath.Join(s.workDir, reverseSessionString(result["result_path"])))
		if err != nil || !strings.Contains(string(raw), `"reason":"detached"`) || !strings.Contains(reverseSessionString(result["message"]), "意外断开") {
			t.Fatalf("detached evidence not retained: %s err=%v result=%v", raw, err, result)
		}
	})
	t.Run("database finish failure is visible after done", func(t *testing.T) {
		s, finished := reverseSessionFixture(t, "finishfail")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		result, err := s.request(ctx, map[string]any{"action": "stop"})
		if err != nil || result["status"] != "failed" || result["is_error"] != true || result["db_status_saved"] != false || <-finished != "completed" {
			t.Fatalf("finish failure result=%v err=%v", result, err)
		}
		if path := reverseSessionString(result["result_path"]); path == "" {
			t.Fatal("local evidence path lost after DB failure")
		} else if _, err := os.Stat(filepath.Join(s.workDir, path)); err != nil {
			t.Fatalf("local evidence unavailable: %v", err)
		}
	})
}

func TestReverseSessionRejectsForeignHandleAndDeviceOverlap(t *testing.T) {
	m := &reverseSessionManager{sessions: map[string]*reverseSession{}}
	workflowCall(t, t.Context(), m.tool(), map[string]any{"action": "read", "session_id": "another-worker"}, true)
	p := reverseRuntimeProfile{Platform: "android", Settings: map[string]any{"adb": "fixture-adb", "adb_port": 5038, "adb_serial": "fixture"}}
	release, err := acquireReverseDevice(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = acquireReverseDevice(p); err == nil {
		t.Fatal("same device admitted twice")
	}
	release()
	release, err = acquireReverseDevice(p)
	if err != nil {
		t.Fatal(err)
	}
	release()
}
