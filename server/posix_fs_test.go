package server

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// requirePosixFileSemantics skips a test when the workspace filesystem cannot do what the
// evidence pipeline needs: publish a blob by hardlink, and atomically replace a
// content-addressed file that was sealed read-only (0444). Windows refuses the second
// with "Access is denied" even for the owner, while POSIX only needs a writable
// directory. That is a property of the host, not of the code under test; the same tests
// run on Linux in CI.
func requirePosixFileSemantics(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("probe"), 0600); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Link(source, link); err != nil {
		t.Skipf("filesystem cannot publish evidence blobs by hardlink (%s): %v", runtime.GOOS, err)
	}
	sealed := filepath.Join(dir, "sealed")
	if err := os.WriteFile(sealed, []byte("sealed"), 0444); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("next"), 0600); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	if err := os.Rename(replacement, sealed); err != nil {
		t.Skipf("filesystem cannot atomically replace a read-only blob (%s): %v", runtime.GOOS, err)
	}
}
