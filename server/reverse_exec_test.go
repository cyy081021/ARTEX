package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// The software workflow gets a whitelisted runner, not a shell. These assertions
// pin the boundary: read-only analysis binaries are always allowed, interpreters
// only for the roles that actually audit code, and nothing else — in particular no
// shell, no chaining helper, no path-qualified binary.
func TestSandboxExecCommandWhitelist(t *testing.T) {
	for _, role := range []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"} {
		for _, name := range []string{"objdump", "readelf", "strings", "nm", "file", "xxd", "sha256sum"} {
			if !sandboxExecCommandAllowed(name, role) {
				t.Fatalf("%s must be allowed for %s", name, role)
			}
		}
	}
	for _, bad := range []string{"bash", "sh", "zsh", "cmd", "powershell", "curl", "wget", "nc", "rm", "mv", "dd", ""} {
		for _, role := range []string{"reverse_static", "reverse_dynamic", "reverse_reviewer"} {
			if sandboxExecCommandAllowed(bad, role) {
				t.Fatalf("%q must not be runnable (role %s)", bad, role)
			}
		}
	}
	if sandboxExecCommandAllowed("/usr/bin/objdump", "reverse_static") {
		t.Fatal("path-qualified commands must be rejected: the whitelist matches basenames only")
	}
	if !sandboxExecCommandAllowed("python3", "reverse_static") || !sandboxExecCommandAllowed("python3", "reverse_dynamic") {
		t.Fatal("audit roles must be able to run python scripts")
	}
	if sandboxExecCommandAllowed("python3", "reverse_reviewer") {
		t.Fatal("the reviewer must stay read-only")
	}
	if list := sandboxExecAllowedList("reverse_reviewer"); strings.Contains(list, "python3") {
		t.Fatalf("reviewer hint must not advertise an interpreter: %s", list)
	}
	if list := sandboxExecAllowedList("reverse_static"); !strings.Contains(list, "python3") {
		t.Fatalf("static hint must advertise the interpreter: %s", list)
	}
}

func TestExecLimitWriterBoundsAndFlags(t *testing.T) {
	w := &execLimitWriter{limit: 8}
	if n, _ := w.Write([]byte("abcdef")); n != 6 {
		t.Fatalf("Write must report the full length, got %d", n)
	}
	if w.Truncated() || string(w.Bytes()) != "abcdef" {
		t.Fatalf("under-limit write must be intact: %q truncated=%v", w.Bytes(), w.Truncated())
	}
	if _, _ = w.Write([]byte("ghijkl")); !w.Truncated() {
		t.Fatal("overflowing write must set truncated")
	}
	if got := string(w.Bytes()); got != "abcdefgh" {
		t.Fatalf("buffer must stop at the limit, got %q", got)
	}
	if tail := tailString([]byte("0123456789"), 4); tail != "6789" {
		t.Fatalf("tailString must keep the end, got %q", tail)
	}
}

// A duplicated tool name is worse than a missing one: the provider either
// rejects the whole request or silently shadows one definition. The reverse
// executor used to be attached twice (inside nativeTools and again at the
// assembly site), so pin the invariant per role.
func TestReverseNativeToolsHaveUniqueNames(t *testing.T) {
	for _, role := range []string{"worker", "reverse_static", "reverse_dynamic", "reverse_reviewer", "reverse_main", "reverse_goals", "reverse_planner"} {
		seen := map[string]bool{}
		for _, tool := range nativeTools(nil, &db.Task{}, agent.RunInfo{}, t.TempDir(), role, &nativeSessionManager{}) {
			if seen[tool.Name()] {
				t.Fatalf("role %s received duplicate tool %q", role, tool.Name())
			}
			seen[tool.Name()] = true
		}
	}
}

// A single audit script can legitimately be a few kilobytes; the old 2 KiB cap
// rejected such a call with a bare "argument too long", which pushed workers
// into writing throwaway one-liners. The budget stays bounded, only larger.
func TestSandboxExecArgumentBudget(t *testing.T) {
	if sandboxExecMaxArgLen < 8192 || sandboxExecMaxArgBytes < sandboxExecMaxArgLen {
		t.Fatalf("argument budget regressed: max_arg=%d total=%d", sandboxExecMaxArgLen, sandboxExecMaxArgBytes)
	}
	if sandboxExecMaxArgBytes > 1<<20 {
		t.Fatalf("argument budget is no longer bounded: %d", sandboxExecMaxArgBytes)
	}
}
