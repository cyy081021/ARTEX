//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Autumn-27/artex/db"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func campaignStorageArtifact(t *testing.T, root string) *db.ReverseArtifact {
	t.Helper()
	key := "tasks/7/reverse/artifacts/fixture.elf"
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, key)), 0700); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 64)
	copy(data, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	data[18] = 62
	if err := os.WriteFile(filepath.Join(root, key), data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return &db.ReverseArtifact{ID: 1, TaskID: 7, Path: key, SizeBytes: 64, SHA256: hex.EncodeToString(sum[:]), Format: "elf"}
}
func TestNativeCampaignLocalArtifactStorage(t *testing.T) {
	for _, mode := range []string{"valid", "wrong_task", "wrong_hash", "traversal", "symlink", "hardlink", "fifo", "directory_link", "writable_intermediate", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			s, err := newNativeCampaignLocalStorage(root)
			if err != nil {
				t.Fatal(err)
			}
			a := campaignStorageArtifact(t, root)
			path := filepath.Join(root, a.Path)
			switch mode {
			case "wrong_task":
				a.TaskID = 8
			case "wrong_hash":
				a.SHA256 = strings.Repeat("0", 64)
			case "traversal":
				a.Path = "tasks/7/reverse/artifacts/../fixture.elf"
			case "symlink", "fifo":
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if mode == "symlink" {
					err = os.Symlink("/etc/passwd", path)
				} else {
					err = unix.Mkfifo(path, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err = os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "writable_intermediate":
				if err = os.Chmod(filepath.Join(root, "tasks/7/reverse"), 0777); err != nil {
					t.Fatal(err)
				}
			case "directory_link":
				dir := filepath.Dir(path)
				if err = os.Rename(dir, dir+"-real"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(dir+"-real", dir); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			err = s.VerifyArtifact(ctx, 7, a)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("%s verification: %v", mode, err)
			}
			if mode == "valid" && a.Path != path {
				t.Fatal("verified path was not resolved for same-namespace runner")
			}
		})
	}
}
func TestNativeCampaignLocalEvidenceStorage(t *testing.T) {
	root := t.TempDir()
	s, err := newNativeCampaignLocalStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	in := nativeCampaignEvidenceWrite{TaskID: 7, CampaignID: 42, AttemptID: 8, Kind: "attempt_final", Operation: "native_campaign", Authority: "candidate-only", Observation: json.RawMessage(`{"candidate_only":true,"findings_created":0}`)}
	var wg sync.WaitGroup
	refs := make(chan *nativeCampaignEvidenceRef, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ref, err := s.PersistEvidence(context.Background(), in)
			refs <- ref
			errs <- err
		}()
	}
	wg.Wait()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-refs, <-refs
	if first.ResultPath != second.ResultPath || first.SHA256 != second.SHA256 {
		t.Fatal("identical evidence was not immutable/idempotent")
	}
	raw, err := os.ReadFile(filepath.Join(root, first.ResultPath))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != first.SHA256 || !bytes.Contains(raw, []byte(`"authority":"candidate-only"`)) {
		t.Fatal("evidence content/authority mismatch")
	}
	entries, err := os.ReadDir(filepath.Dir(filepath.Join(root, first.ResultPath)))
	if err != nil || len(entries) != 1 {
		t.Fatalf("left partial files: %d %v", len(entries), err)
	}
	first.Observation[0] = 'x'
	if !json.Valid(in.Observation) {
		t.Fatal("evidence handoff aliased input")
	}
	in.Authority = "controlled-replay"
	if _, err = s.PersistEvidence(context.Background(), in); err == nil {
		t.Fatal("authority upgrade accepted")
	}
}
func TestNativeCampaignLocalEvidenceRejectsUnsafePath(t *testing.T) {
	root := t.TempDir()
	s, _ := newNativeCampaignLocalStorage(root)
	parent := filepath.Join(root, "tasks/7/reverse/campaigns/42")
	if err := os.MkdirAll(parent, 0700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(parent, "evidence")); err != nil {
		t.Fatal(err)
	}
	in := nativeCampaignEvidenceWrite{TaskID: 7, CampaignID: 42, AttemptID: 8, Kind: "attempt_final", Operation: "native_campaign", Authority: "candidate-only", Observation: json.RawMessage(`{}`)}
	if _, err := s.PersistEvidence(context.Background(), in); err == nil {
		t.Fatal("evidence symlink accepted")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside trusted evidence root")
	}
}

func TestNativeCampaignEvidenceReuseHonorsFinalDeadline(t *testing.T) {
	root := t.TempDir()
	key := "tasks/7/reverse/campaigns/42/evidence/proof.json"
	data := []byte(`{"candidate_only":true}`)
	if err := publishNativeCampaignEvidence(context.Background(), root, key, data); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reached := false
	fs := nativeCampaignCAS{syncDir: func(fd int) error {
		err := unix.Fsync(fd)
		path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if path == filepath.Join(root, filepath.Dir(key)) {
			reached = true
			cancel()
		}
		return err
	}}
	if err := fs.publishEvidence(ctx, root, key, data); !errors.Is(err, context.Canceled) || !reached {
		t.Fatalf("reuse crossed cutoff as success: reached=%v err=%v", reached, err)
	}
	raw, err := os.ReadFile(filepath.Join(root, key))
	if err != nil || !bytes.Equal(raw, data) {
		t.Fatal("deadline mutated immutable evidence")
	}
}
