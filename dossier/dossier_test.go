package dossier

import (
	"archive/zip"
	"bytes"
	"testing"
)

func TestLocalSnapshotIdentityAndReferences(t *testing.T) {
	a := Bundle{Scenario: Open, Name: "catalog", Goal: "compare fixtures", Commit: "v1", Files: []File{{Kind: "source", Name: "main.txt", Data: []byte("first\nsecond")}}}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	b := a
	b.Snapshot = ""
	b.Files = []File{{Kind: "source", Name: "main.txt", Data: []byte("first\nchanged")}}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if b.Snapshot == a.Snapshot {
		t.Fatal("dirty worktree lost")
	}
	log := File{Name: "ci.txt", Kind: "evidence", Subject: b.Snapshot, Data: []byte("revision B")}
	a.Files = append(a.Files, log, log)
	if err := a.Normalize(); err != nil || len(a.Files) != 2 {
		t.Fatalf("dedup: %v", err)
	}
	a.Notes = []Note{{State: "observed", Text: "wrong build", File: log.Name, Hash: Digest(log.Data), Subject: a.Snapshot}}
	if a.Normalize() == nil {
		t.Fatal("accepted a CI record from another snapshot")
	}
	a.Notes = []Note{{State: "source", Text: "second line", File: "main.txt", Hash: a.Files[0].Hash, Subject: a.Snapshot, Line: 2}, {State: "unresolved", Text: "no matching runtime record"}}
	if err := a.Normalize(); err != nil {
		t.Fatal(err)
	}
	a.Notes[0].Line = 3
	if a.Normalize() == nil {
		t.Fatal("accepted stale line")
	}
}
func TestReleaseIdentityAndZIP(t *testing.T) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	f, err := z.Create("lib/meta.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("meta"))
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := Expand(File{Name: "demo.zip", Kind: "package", Data: buf.Bytes()}, MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, File{Kind: "package", Name: "demo.zip", Data: []byte("different")})
	b := Bundle{Scenario: Closed, Name: "demo", Goal: "compare deliveries", Files: files}
	if err := b.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(b.Files) != 3 || b.Files[1].Parent != b.Files[0].Hash || b.Files[2].Hash == b.Files[0].Hash {
		t.Fatal("lost release identity")
	}
	if err := b.VerifyChildren(); err != nil {
		t.Fatal(err)
	}
	changed := b
	changed.Files = append([]File(nil), b.Files...)
	changed.Files[1].Data = []byte("different member")
	changed.Files[1].Hash = Digest(changed.Files[1].Data)
	if changed.VerifyChildren() == nil {
		t.Fatal("accepted a member that differs from the archived ZIP")
	}
	b.Notes = []Note{{State: "source", Text: "component record", File: b.Files[1].Name, Hash: b.Files[1].Hash, Subject: b.Files[2].Hash}}
	if b.Normalize() == nil {
		t.Fatal("wrong component parent accepted")
	}
	if _, err := Expand(files[0], len(buf.Bytes())); err == nil {
		t.Fatal("unpacked bytes not limited")
	}
}
