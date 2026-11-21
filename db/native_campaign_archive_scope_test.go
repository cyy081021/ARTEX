package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func campaignArchiveScopeFixture(t *testing.T) *TaskArchiveSnapshot {
	t.Helper()
	s := &TaskArchiveSnapshot{FormatVersion: 6, TaskID: 1, Tables: map[string]json.RawMessage{}}
	for _, name := range nativeCampaignArchiveTables {
		s.Tables[name] = json.RawMessage(`[]`)
	}
	put := func(name string, rows ...map[string]any) {
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		s.Tables[name] = raw
	}
	sha := strings.Repeat("a", 64)
	key := nativeCampaignStorageKey(1, sha)
	_, specHash, err := CanonicalNativeCampaignSpec(json.RawMessage(`{"engine":"afl++"}`))
	if err != nil {
		t.Fatal(err)
	}
	put("reverse_artifacts", map[string]any{"id": 10, "task_id": 1, "sha256": sha})
	put("reverse_runtime_runs", map[string]any{"id": 20, "task_id": 1, "artifact_id": 10})
	put("reverse_native_runs", map[string]any{"run_id": 20, "task_id": 1, "artifact_id": 10, "mode": NativeModeCampaign})
	put("native_campaigns", map[string]any{"id": 2, "task_id": 1, "artifact_id": 10, "artifact_sha256": sha, "spec": map[string]any{"engine": "afl++"}, "spec_hash": specHash, "current_attempt_id": 3, "latest_checkpoint_id": 7})
	put("native_campaign_attempts", map[string]any{"id": 3, "task_id": 1, "campaign_id": 2, "resource_hold": false, "state": "paused", "native_run_id": 20, "runtime_run_id": 20, "checkpoint_id": 7, "evidence_manifest_id": 8})
	put("native_campaign_objects", map[string]any{"id": 4, "task_id": 1, "sha256": sha, "length": 1, "storage_key": key})
	entry := NativeCampaignEntryInput{ObjectID: 4, SHA256: sha, Length: 1, StorageKey: key, SourceType: "seed", SourceRef: "种子/<>&"}
	canonical, err := CanonicalNativeCampaignManifest(2, 3, []NativeCampaignEntryInput{entry})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	put("native_campaign_corpus_manifests", map[string]any{"id": 5, "task_id": 1, "campaign_id": 2, "attempt_id": 3, "format_version": 1, "manifest_sha256": hex.EncodeToString(sum[:]), "entry_count": 1, "total_bytes": 1, "truncated": false})
	put("native_campaign_corpus_entries", map[string]any{"id": 6, "task_id": 1, "manifest_id": 5, "ordinal": 0, "object_id": 4, "sha256": sha, "length": 1, "storage_key": key, "source_type": "seed", "source_ref": entry.SourceRef})
	put("native_campaign_checkpoints", map[string]any{"id": 7, "task_id": 1, "campaign_id": 2, "attempt_id": 3, "manifest_id": 5, "state": "verified", "format_version": 1, "entry_count": 1, "total_bytes": 1, "truncated": false})
	put("native_campaign_evidence", map[string]any{"id": 8, "task_id": 1, "campaign_id": 2, "attempt_id": 3, "result_path": "tasks/1/reverse/campaigns/evidence.json", "sha256": sha, "authority": "candidate-only", "operation": "native_campaign"})
	put("native_campaign_events", map[string]any{"id": 9, "task_id": 1, "campaign_id": 2, "attempt_id": 3})
	put("native_campaign_requests", map[string]any{"id": 10, "task_id": 1, "campaign_id": 2})
	return s
}

func TestNativeCampaignArchiveScopePure(t *testing.T) {
	if err := validateNativeCampaignArchiveScope(campaignArchiveScopeFixture(t)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, table, field string
		value              any
	}{
		{"foreign_task", "native_campaign_objects", "task_id", 2},
		{"dangling_attempt", "native_campaign_events", "attempt_id", 999},
		{"foreign_pointer", "native_campaigns", "current_attempt_id", 999},
		{"runtime_binding", "native_campaign_attempts", "runtime_run_id", 999},
		{"artifact_hash", "native_campaigns", "artifact_sha256", strings.Repeat("b", 64)},
		{"spec_hash", "native_campaigns", "spec_hash", strings.Repeat("b", 64)},
		{"manifest_hash", "native_campaign_corpus_manifests", "manifest_sha256", strings.Repeat("b", 64)},
		{"ordinal_gap", "native_campaign_corpus_entries", "ordinal", 1},
		{"object_bytes", "native_campaign_corpus_entries", "length", 2},
		{"checkpoint_count", "native_campaign_checkpoints", "entry_count", 2},
		{"evidence_path", "native_campaign_evidence", "result_path", "/host/secret"},
		{"authority", "native_campaign_evidence", "authority", "confirmed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := campaignArchiveScopeFixture(t)
			rows, err := decodeArchiveRows(s.Tables[tc.table])
			if err != nil {
				t.Fatal(err)
			}
			rows[0][tc.field] = tc.value
			s.Tables[tc.table], _ = json.Marshal(rows)
			if err := validateNativeCampaignArchiveScope(s); err == nil {
				t.Fatal("invalid graph accepted")
			}
		})
	}
	for _, name := range nativeCampaignArchiveTables {
		t.Run("missing_"+name, func(t *testing.T) {
			s := campaignArchiveScopeFixture(t)
			delete(s.Tables, name)
			if err := validateNativeCampaignArchiveScope(s); err == nil {
				t.Fatal("missing table accepted")
			}
		})
	}
	s := campaignArchiveScopeFixture(t)
	rows, _ := decodeArchiveRows(s.Tables["native_campaign_objects"])
	s.Tables["native_campaign_objects"], _ = json.Marshal(append(rows, rows[0]))
	if err := validateNativeCampaignArchiveScope(s); err == nil {
		t.Fatal("duplicate identity accepted")
	}
	for version := 1; version <= 5; version++ {
		old := &TaskArchiveSnapshot{FormatVersion: version, TaskID: 1, Tables: map[string]json.RawMessage{}}
		if err := validateNativeCampaignArchiveScope(old); err != nil {
			t.Fatal(err)
		}
		old.Tables["native_campaigns"] = json.RawMessage(`[]`)
		if err := validateNativeCampaignArchiveScope(old); err == nil {
			t.Fatal("legacy smuggling accepted")
		}
	}
}

func TestNativeCampaignArchiveScopeRejectsCompositeScalars(t *testing.T) {
	for _, value := range []any{map[string]any{"bad": true}, []any{"bad"}} {
		for _, fields := range [][4]string{{"native_campaigns", "artifact_sha256", "reverse_artifacts", "sha256"}, {"native_campaign_checkpoints", "truncated", "native_campaign_corpus_manifests", "truncated"}} {
			s := campaignArchiveScopeFixture(t)
			for i := 0; i < 4; i += 2 {
				rows, _ := decodeArchiveRows(s.Tables[fields[i]])
				rows[0][fields[i+1]] = value
				s.Tables[fields[i]], _ = json.Marshal(rows)
			}
			if err := validateNativeCampaignArchiveScope(s); err == nil {
				t.Fatal("composite scalar accepted")
			}
		}
	}
	for _, tc := range []struct {
		table, field string
		value        any
	}{{"native_campaign_checkpoints", "state", "pending"}, {"native_campaign_evidence", "operation", "other"}, {"reverse_runtime_runs", "artifact_id", 99}} {
		s := campaignArchiveScopeFixture(t)
		rows, _ := decodeArchiveRows(s.Tables[tc.table])
		rows[0][tc.field] = tc.value
		s.Tables[tc.table], _ = json.Marshal(rows)
		if err := validateNativeCampaignArchiveScope(s); err == nil {
			t.Fatal("invalid pointer or binding accepted")
		}
	}
}

func TestNativeCampaignArchiveFileReferences(t *testing.T) {
	snapshot := campaignArchiveScopeFixture(t)
	refs, err := NativeCampaignArchiveFiles(snapshot)
	if err != nil || len(refs) != 2 {
		t.Fatalf("refs=%+v %v", refs, err)
	}
	if refs[0].Length != 1 || refs[0].MaxBytes != 4096 || refs[1].Length != 0 || refs[1].MaxBytes != 512<<10 {
		t.Fatalf("incorrect file bounds %+v", refs)
	}
	delete(snapshot.Tables, "native_campaign_objects")
	if _, err = NativeCampaignArchiveFiles(snapshot); err == nil {
		t.Fatal("invalid graph exported references")
	}
}
