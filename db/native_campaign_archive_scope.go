package db

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

var nativeCampaignArchiveTables = []string{
	"native_campaigns", "native_campaign_attempts", "native_campaign_objects",
	"native_campaign_corpus_manifests", "native_campaign_corpus_entries",
	"native_campaign_checkpoints", "native_campaign_evidence",
	"native_campaign_requests", "native_campaign_events",
}

// validateNativeCampaignArchiveScope validates the complete Campaign graph.
// Both v6 compaction and restore validate this graph before their transactions.
// It does not authorize execution or prove referenced filesystem contents exist.
func validateNativeCampaignArchiveScope(s *TaskArchiveSnapshot) error {
	if s == nil {
		return fmt.Errorf("missing archive snapshot")
	}
	if s.FormatVersion < 6 {
		for _, name := range nativeCampaignArchiveTables {
			if _, ok := s.Tables[name]; ok {
				return fmt.Errorf("legacy archive contains Campaign table")
			}
		}
		return nil
	}
	if s.FormatVersion != 6 || s.TaskID <= 0 {
		return fmt.Errorf("invalid Campaign archive version or task")
	}
	tables := map[string]map[int64]map[string]any{}
	load := func(name, key string, required bool) error {
		raw, ok := s.Tables[name]
		if !ok {
			if required {
				return fmt.Errorf("missing %s table", name)
			}
			tables[name] = map[int64]map[string]any{}
			return nil
		}
		if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("invalid %s table", name)
		}
		rows, err := decodeArchiveRows(raw)
		if err != nil {
			return fmt.Errorf("invalid %s table", name)
		}
		index := map[int64]map[string]any{}
		for _, r := range rows {
			id, ok := jsonInt64(r[key])
			if !ok || id <= 0 {
				return fmt.Errorf("invalid %s identity", name)
			}
			if _, dup := index[id]; dup {
				return fmt.Errorf("duplicate %s identity", name)
			}
			task, ok := jsonInt64(r["task_id"])
			if !ok || task != s.TaskID {
				return fmt.Errorf("foreign %s row", name)
			}
			index[id] = r
		}
		tables[name] = index
		return nil
	}
	for _, name := range nativeCampaignArchiveTables {
		if err := load(name, "id", true); err != nil {
			return err
		}
	}
	for _, name := range []string{"reverse_artifacts", "reverse_runtime_runs", "reverse_native_runs"} {
		key := "id"
		if name == "reverse_native_runs" {
			key = "run_id"
		}
		if err := load(name, key, false); err != nil {
			return err
		}
	}
	ref := func(row map[string]any, field, table string, nullable bool) (map[string]any, error) {
		value, exists := row[field]
		if nullable && (!exists || value == nil) {
			return nil, nil
		}
		id, ok := jsonInt64(value)
		if !ok || id <= 0 {
			return nil, fmt.Errorf("invalid %s reference", field)
		}
		target, ok := tables[table][id]
		if !ok {
			return nil, fmt.Errorf("dangling %s reference", field)
		}
		return target, nil
	}
	equal := func(a map[string]any, af string, b map[string]any, bf string) bool {
		x, xok := jsonInt64(a[af])
		y, yok := jsonInt64(b[bf])
		return xok && yok && x == y
	}
	equalString := func(a map[string]any, af string, b map[string]any, bf string) bool {
		x, xok := a[af].(string)
		y, yok := b[bf].(string)
		return xok && yok && x == y
	}
	for _, c := range tables["native_campaigns"] {
		if c["state"] == "running" || c["state"] == "stopping" {
			return fmt.Errorf("active Campaign cannot be archived")
		}

		a, err := ref(c, "artifact_id", "reverse_artifacts", false)
		if err != nil {
			return err
		}
		artifactSHA, shaOK := c["artifact_sha256"].(string)
		if !shaOK || validateNativeCampaignSHA256(artifactSHA, "artifact_sha256") != nil || !equalString(c, "artifact_sha256", a, "sha256") {
			return fmt.Errorf("Campaign artifact hash mismatch")
		}
		raw, err := json.Marshal(c["spec"])
		if err != nil {
			return fmt.Errorf("invalid Campaign spec")
		}
		_, digest, err := CanonicalNativeCampaignSpec(raw)
		if err != nil || c["spec_hash"] != digest {
			return fmt.Errorf("Campaign spec hash mismatch")
		}
		for _, p := range []struct{ field, table string }{{"current_attempt_id", "native_campaign_attempts"}, {"latest_checkpoint_id", "native_campaign_checkpoints"}} {
			target, err := ref(c, p.field, p.table, true)
			if err != nil {
				return err
			}
			if target != nil && p.field == "latest_checkpoint_id" && target["state"] != "verified" {
				return fmt.Errorf("unverified Campaign checkpoint pointer")
			}
			if target != nil && !equal(target, "campaign_id", c, "id") {
				return fmt.Errorf("foreign Campaign pointer")
			}
		}
	}
	for _, a := range tables["native_campaign_attempts"] {
		hold, ok := a["resource_hold"].(bool)
		if !ok || hold {
			return fmt.Errorf("held Campaign attempt cannot be archived")
		}
		if state, ok := a["state"].(string); !ok {
			return fmt.Errorf("invalid archived attempt state")
		} else if _, active := nativeCampaignActiveAttemptStates[state]; active {
			return fmt.Errorf("active Campaign attempt cannot be archived")
		}

		c, err := ref(a, "campaign_id", "native_campaigns", false)
		if err != nil {
			return err
		}
		nr, err := ref(a, "native_run_id", "reverse_native_runs", false)
		if err != nil {
			return err
		}
		rr, err := ref(a, "runtime_run_id", "reverse_runtime_runs", false)
		if err != nil {
			return err
		}
		if !equal(nr, "run_id", rr, "id") || !equal(nr, "artifact_id", c, "artifact_id") || !equal(rr, "artifact_id", c, "artifact_id") || nr["mode"] != NativeModeCampaign {
			return fmt.Errorf("invalid Campaign run binding")
		}
		for _, p := range []struct{ field, table string }{{"checkpoint_id", "native_campaign_checkpoints"}, {"evidence_manifest_id", "native_campaign_evidence"}} {
			target, err := ref(a, p.field, p.table, true)
			if err != nil {
				return err
			}
			if target != nil && p.field == "checkpoint_id" && target["state"] != "verified" {
				return fmt.Errorf("unverified Attempt checkpoint pointer")
			}
			if target != nil && (!equal(target, "attempt_id", a, "id") || !equal(target, "campaign_id", c, "id")) {
				return fmt.Errorf("foreign Attempt pointer")
			}
		}
	}
	for _, o := range tables["native_campaign_objects"] {
		sha, ok := o["sha256"].(string)
		length, lok := jsonInt64(o["length"])
		if !ok || validateNativeCampaignSHA256(sha, "sha256") != nil || !lok || length < 1 || length > 4096 || o["storage_key"] != nativeCampaignStorageKey(s.TaskID, sha) {
			return fmt.Errorf("invalid Campaign object")
		}
	}
	// Every attempt-owned row must bind the same source Campaign, not merely task.
	for _, name := range []string{"native_campaign_corpus_manifests", "native_campaign_checkpoints", "native_campaign_evidence", "native_campaign_events"} {
		for _, r := range tables[name] {
			c, err := ref(r, "campaign_id", "native_campaigns", false)
			if err != nil {
				return err
			}
			a, err := ref(r, "attempt_id", "native_campaign_attempts", name == "native_campaign_events")
			if err != nil {
				return err
			}
			if a != nil && !equal(a, "campaign_id", c, "id") {
				return fmt.Errorf("foreign Campaign attempt")
			}
		}
	}
	for _, r := range tables["native_campaign_requests"] {
		if _, err := ref(r, "campaign_id", "native_campaigns", true); err != nil {
			return err
		}
	}
	entries := map[int64][]NativeCampaignEntryInput{}
	for _, r := range tables["native_campaign_corpus_entries"] {
		m, err := ref(r, "manifest_id", "native_campaign_corpus_manifests", false)
		if err != nil {
			return err
		}
		o, err := ref(r, "object_id", "native_campaign_objects", false)
		if err != nil {
			return err
		}
		if !equalString(r, "sha256", o, "sha256") || !equalString(r, "storage_key", o, "storage_key") || !equal(r, "length", o, "length") {
			return fmt.Errorf("Campaign entry object mismatch")
		}
		if _, ok := jsonInt64(r["ordinal"]); !ok {
			return fmt.Errorf("invalid Campaign ordinal")
		}
		raw, _ := json.Marshal(r)
		var e NativeCampaignCorpusEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return fmt.Errorf("invalid Campaign entry")
		}
		mid, _ := jsonInt64(m["id"])
		entries[mid] = append(entries[mid], NativeCampaignEntryInput{Ordinal: e.Ordinal, ObjectID: e.ObjectID, SHA256: e.SHA256, Length: e.Length, StorageKey: e.StorageKey, SourceType: e.SourceType, SourceRef: e.SourceRef})
	}
	for id, r := range tables["native_campaign_corpus_manifests"] {
		raw, _ := json.Marshal(r)
		var m NativeCampaignCorpusManifest
		if err := json.Unmarshal(raw, &m); err != nil || m.FormatVersion != 1 {
			return fmt.Errorf("invalid Campaign manifest")
		}
		es := entries[id]
		sort.Slice(es, func(i, j int) bool { return es[i].Ordinal < es[j].Ordinal })
		seen := map[string]bool{}
		for i, e := range es {
			if e.Ordinal != i || seen[e.SHA256] {
				return fmt.Errorf("invalid Campaign manifest ordinals or duplicate object")
			}
			seen[e.SHA256] = true
		}
		in := NativeCampaignManifestInput{TaskID: s.TaskID, CampaignID: m.CampaignID, AttemptID: m.AttemptID, ManifestSHA256: m.ManifestSHA256, EntryCount: m.EntryCount, TotalBytes: m.TotalBytes, Truncated: m.Truncated, Entries: es}
		if err := validateNativeCampaignManifestInput(&in, true); err != nil {
			return fmt.Errorf("invalid Campaign manifest bounds")
		}
		canonical, err := CanonicalNativeCampaignManifest(m.CampaignID, m.AttemptID, es)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(canonical)
		if hex.EncodeToString(hash[:]) != m.ManifestSHA256 {
			return fmt.Errorf("Campaign manifest hash mismatch")
		}
	}
	for _, r := range tables["native_campaign_checkpoints"] {
		m, err := ref(r, "manifest_id", "native_campaign_corpus_manifests", false)
		if err != nil {
			return err
		}
		for _, field := range []string{"campaign_id", "attempt_id", "format_version", "entry_count", "total_bytes"} {
			if !equal(r, field, m, field) {
				return fmt.Errorf("Campaign checkpoint manifest mismatch")
			}
		}
		rt, rok := r["truncated"].(bool)
		mt, mok := m["truncated"].(bool)
		if !rok || !mok || rt != mt {
			return fmt.Errorf("Campaign checkpoint truncation mismatch")
		}
	}
	for _, r := range tables["native_campaign_evidence"] {
		path, ok := r["result_path"].(string)
		sha, sok := r["sha256"].(string)
		if !ok || !validNativeCampaignResultPath(s.TaskID, path) || !sok || validateNativeCampaignSHA256(sha, "sha256") != nil || r["operation"] != "native_campaign" || r["authority"] != "candidate-only" {
			return fmt.Errorf("invalid Campaign evidence")
		}
	}
	return nil
}
