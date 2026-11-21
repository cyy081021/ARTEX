package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func campaignArchiveHistoryFixture(t *testing.T, d *DB, state string) (*Task, *NativeCampaign) {
	t.Helper()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, artifact := newNativeCampaignTask(t, d, "archive-history-"+state)
	c := t3CreateDraft(t, d, task, artifact, "archive-history-"+state)
	if state != "draft" {
		c = t3Start(t, d, c, c.StateVersion, t3ReqID("archive-start"), nil)
	}
	if state != "draft" && state != "queued" {
		a := t3MustClaim(t, d, task, c, "archive-owner").Attempt
		c = t3ReloadCampaign(t, d, c)
		if state == "paused" || state == "cancelled" {
			cmd := NativeCampaignStateCommand{TaskID: task.ID, CampaignID: c.ID, ExpectedStateVersion: c.StateVersion, RequestID: t3ReqID("archive-stop")}
			var stopErr error
			if state == "paused" {
				_, stopErr = d.PauseNativeCampaign(context.Background(), t3AllowAuth, cmd)
			} else {
				_, stopErr = d.CancelNativeCampaign(context.Background(), t3AllowAuth, cmd)
			}
			if stopErr != nil {
				t.Fatal(stopErr)
			}
		}
		id := nativeCampaignLeaseIdentityOf(a)
		sha := nativeCampaignHash("A")
		entries := []NativeCampaignEntryInput{{Ordinal: 0, SHA256: sha, Length: 1, StorageKey: nativeCampaignStorageKey(task.ID, sha), SourceType: "seed", SourceRef: "seed.bin"}}
		raw, err := CanonicalNativeCampaignManifest(c.ID, a.ID, entries)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		cp, err := d.CommitVerifiedNativeCampaignCheckpoint(context.Background(), NativeCampaignCheckpointCommit{NativeCampaignLeaseIdentity: id, Manifest: NativeCampaignManifestInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, ManifestSHA256: hex.EncodeToString(sum[:]), EntryCount: 1, TotalBytes: 1, Entries: entries}})
		if err != nil {
			t.Fatal(err)
		}
		ev, err := d.PrepareNativeCampaignFinalEvidence(context.Background(), id, NativeCampaignEvidenceInput{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, Kind: "attempt_final", ResultPath: fmt.Sprintf("tasks/%d/reverse/campaigns/final.json", task.ID), SHA256: nativeCampaignHash("final"), Observation: []byte(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = d.FinalizeNativeCampaignAttempt(context.Background(), t3AllowAuth, NativeCampaignFinalizeCommand{TaskID: task.ID, CampaignID: c.ID, AttemptID: a.ID, FencingToken: a.FencingToken, LeaseOwner: a.LeaseOwner, LeaseInstance: a.LeaseInstance, TargetState: state, Phase: "finalize", CleanupStatus: "verified", CheckpointID: &cp.ID, EvidenceID: ev.ID, TerminationReason: "fixture", ActorKind: "admin"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`UPDATE tasks SET paused=true WHERE id=$1`, task.ID); err != nil {
		t.Fatal(err)
	}
	return task, t3ReloadCampaign(t, d, c)
}

func TestNativeCampaignArchiveV6NoExec(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	for _, state := range []string{"draft", "queued", "paused", "interrupted", "completed", "failed", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			task, c := campaignArchiveHistoryFixture(t, d, state)
			archive, err := d.QueueTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			claimTaskArchiveFixture(t, d, archive.ID)
			snapshot, err := d.SnapshotTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.FormatVersion != 6 {
				t.Fatalf("snapshot version %d", snapshot.FormatVersion)
			}
			if err = validateNativeCampaignArchiveScope(snapshot); err != nil {
				t.Fatal(err)
			}
			for _, table := range nativeCampaignArchiveTables {
				if _, ok := snapshot.Tables[table]; !ok {
					t.Fatalf("missing %s", table)
				}
			}
			if err = d.CompleteTaskArchive(archive.ID, snapshot, "test-campaign.tar", nativeCampaignHash(state), 1, 1); err != nil {
				t.Fatal(err)
			}
			for _, table := range nativeCampaignArchiveTables {
				var n int
				if err = d.QueryRow(`SELECT count(*) FROM `+table+` WHERE task_id=$1`, task.ID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("hot Campaign rows remain %s=%d %v", table, n, err)
				}
			}
			var clear bool
			if err = d.QueryRow(`SELECT compaction_txid IS NULL FROM task_archives WHERE id=$1`, archive.ID).Scan(&clear); err != nil || !clear {
				t.Fatal("successful compaction retained transaction permission")
			}
			if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
				t.Fatal(err)
			}
			claimTaskArchiveFixture(t, d, archive.ID)
			if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
				t.Fatal(err)
			}
			if err = d.CompleteTaskArchiveRestore(archive.ID); err != nil {
				t.Fatal(err)
			}
			got, err := d.NativeCampaign(context.Background(), task.ID, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if got.State != state || got.DesiredState != "none" || got.SpecHash != c.SpecHash || got.ChargedBudgetMS != c.ChargedBudgetMS {
				t.Fatalf("history altered: before=%+v after=%+v", c, got)
			}
			restored, err := d.NativeCampaignArchiveRestored(context.Background(), task.ID, c.ID)
			if err != nil || !restored {
				t.Fatal("restore provenance missing")
			}
			if _, err = d.StartNativeCampaign(context.Background(), t3AllowAuth, NativeCampaignStateCommand{TaskID: task.ID, CampaignID: c.ID, ExpectedStateVersion: got.StateVersion, RequestID: t3ReqID("restored-start")}); NativeCampaignErrorCode(err) != "archive_restore_not_executable" {
				t.Fatalf("restored record executable: %v", err)
			}
			for _, table := range nativeCampaignArchiveTables {
				var n int64
				if err = d.QueryRow(`SELECT count(*) FROM `+table+` WHERE task_id=$1`, task.ID).Scan(&n); err != nil {
					t.Fatal(err)
				}
				want := snapshot.DataCounts[table]
				if table == "native_campaign_events" {
					want++
				}
				if n != want {
					t.Fatalf("restored %s count=%d want=%d", table, n, want)
				}
			}
			after, err := d.SnapshotTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, table := range nativeCampaignArchiveTables {
				beforeRows, err := decodeArchiveRows(snapshot.Tables[table])
				if err != nil {
					t.Fatal(err)
				}
				afterRows, err := decodeArchiveRows(after.Tables[table])
				if err != nil {
					t.Fatal(err)
				}
				if table == "native_campaigns" {
					for _, r := range beforeRows {
						r["desired_state"] = "none"
					}
				}
				if table == "native_campaign_events" {
					filtered := afterRows[:0]
					for _, r := range afterRows {
						if r["kind"] != nativeCampaignArchiveRestoredEvent {
							filtered = append(filtered, r)
						}
					}
					afterRows = filtered
				}
				beforeJSON, _ := json.Marshal(beforeRows)
				afterJSON, _ := json.Marshal(afterRows)
				if !bytes.Equal(beforeJSON, afterJSON) {
					t.Fatalf("same-ID history content changed: %s", table)
				}
			}
			artifact, err := d.GetReverseArtifact(task.ID, c.ArtifactID)
			if err != nil || artifact == nil {
				t.Fatal("artifact not restored")
			}
			fresh := t3CreateDraft(t, d, task, artifact, "post-restore-sequence")
			if fresh.ID <= c.ID {
				t.Fatal("same-database sequence regressed")
			}
		})
	}
}

func TestNativeCampaignArchiveRejectsStaleSnapshot(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, c := campaignArchiveHistoryFixture(t, d, "draft")
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.FailTaskArchiveJob(archive.ID, Archiving, fmt.Errorf("synthetic packaging failure")); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CreateNativeCampaignEvent(context.Background(), NativeCampaignEventInput{TaskID: task.ID, CampaignID: c.ID, Kind: "after.failed.snapshot", Payload: []byte(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchive(task.ID); err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "stale.tar", nativeCampaignHash("stale"), 1, 1); err == nil {
		t.Fatal("stale snapshot compacted newer rows")
	}
	var clear bool
	if err = d.QueryRow(`SELECT compaction_txid IS NULL FROM task_archives WHERE id=$1`, archive.ID).Scan(&clear); err != nil || !clear {
		t.Fatal("failed compaction retained permission")
	}
	if _, err = d.NativeCampaign(context.Background(), task.ID, c.ID); err != nil {
		t.Fatal("failed compaction lost campaign")
	}
	fresh, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchive(archive.ID, fresh, "fresh.tar", nativeCampaignHash("fresh"), 1, 1); err != nil {
		t.Fatal(err)
	}
}

// A failure after several DELETEs must roll back data and the transaction token.
func TestNativeCampaignArchiveCompactionRollback(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _ := campaignArchiveHistoryFixture(t, d, "paused")
	other, _ := campaignArchiveHistoryFixture(t, d, "paused")
	otherBefore, err := d.SnapshotTaskArchive(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("audit_campaign_compaction_%d", task.ID)
	if _, err = d.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.task_id=%d THEN IF EXISTS(SELECT 1 FROM native_campaign_events WHERE task_id=OLD.task_id) OR EXISTS(SELECT 1 FROM native_campaign_evidence WHERE task_id=OLD.task_id) OR EXISTS(SELECT 1 FROM native_campaign_checkpoints WHERE task_id=OLD.task_id) OR EXISTS(SELECT 1 FROM native_campaign_corpus_entries WHERE task_id=OLD.task_id) OR EXISTS(SELECT 1 FROM native_campaign_corpus_manifests WHERE task_id=OLD.task_id) THEN RAISE EXCEPTION 'wrong injection stage'; END IF; RAISE EXCEPTION 'injected middle compaction failure'; END IF; RETURN OLD; END $$; CREATE TRIGGER %s BEFORE DELETE ON native_campaign_objects FOR EACH ROW EXECUTE FUNCTION %s()`, name, task.ID, name, name)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = d.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON native_campaign_objects; DROP FUNCTION IF EXISTS %s()`, name, name))
	}()
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "rollback.tar", nativeCampaignHash("rollback"), 1, 1); err == nil || !strings.Contains(err.Error(), "injected middle compaction failure") {
		t.Fatalf("did not reach injected middle DELETE: %v", err)
	}
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = compareNativeCampaignArchiveSnapshotTx(tx, snapshot); err != nil {
		t.Fatalf("partial rollback: %v", err)
	}
	if err = compareNativeCampaignArchiveSnapshotTx(tx, otherBefore); err != nil {
		t.Fatalf("other task changed: %v", err)
	}
	var clear bool
	if err = tx.QueryRow(`SELECT compaction_txid IS NULL AND phase<>'database_compacting' FROM task_archives WHERE id=$1`, archive.ID).Scan(&clear); err != nil || !clear {
		t.Fatalf("permission survived rollback: %v", err)
	}
}

func TestNativeCampaignArchiveRearchivePreservesMarkers(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, c := campaignArchiveHistoryFixture(t, d, "paused")
	var previous []byte
	for cycle := 1; cycle <= 2; cycle++ {
		archive, err := d.QueueTaskArchive(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		claimTaskArchiveFixture(t, d, archive.ID)
		snapshot, err := d.SnapshotTaskArchive(task.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.CompleteTaskArchive(archive.ID, snapshot, "rearchive.tar", nativeCampaignHash("rearchive"), 1, 1); err != nil {
			t.Fatal(err)
		}
		if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
			t.Fatal(err)
		}
		claimTaskArchiveFixture(t, d, archive.ID)
		if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
			t.Fatal(err)
		}
		if err = d.CompleteTaskArchiveRestore(archive.ID); err != nil {
			t.Fatal(err)
		}
		var n int
		if err = d.QueryRow(`SELECT count(*) FROM native_campaign_events WHERE task_id=$1 AND campaign_id=$2 AND kind=$3`, task.ID, c.ID, nativeCampaignArchiveRestoredEvent).Scan(&n); err != nil || n != cycle {
			t.Fatalf("marker history=%d want=%d %v", n, cycle, err)
		}
		var earliest []byte
		if err = d.QueryRow(`SELECT row_to_json(e) FROM native_campaign_events e WHERE task_id=$1 AND campaign_id=$2 AND kind=$3 ORDER BY id LIMIT 1`, task.ID, c.ID, nativeCampaignArchiveRestoredEvent).Scan(&earliest); err != nil {
			t.Fatal(err)
		}
		if cycle == 1 {
			previous = append([]byte(nil), earliest...)
		} else if !bytes.Equal(previous, earliest) {
			t.Fatal("original restore provenance was changed")
		}
	}
}

func TestNativeCampaignArchiveLegacyVersions(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if err = d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err = d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 5; version++ {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			task, artifact := newNativeCampaignTask(t, d, "legacy-no-campaign")
			archive, err := d.QueueTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			claimTaskArchiveFixture(t, d, archive.ID)
			snapshot, err := d.SnapshotTaskArchive(task.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err = d.CompleteTaskArchive(archive.ID, snapshot, "legacy.tar", nativeCampaignHash("legacy"), 1, 1); err != nil {
				t.Fatal(err)
			}
			snapshot.FormatVersion = version
			for _, table := range nativeCampaignArchiveTables {
				delete(snapshot.Tables, table)
				delete(snapshot.DataCounts, table)
			}
			if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
				t.Fatal(err)
			}
			claimTaskArchiveFixture(t, d, archive.ID)
			if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
				t.Fatal(err)
			}
			if err = d.CompleteTaskArchiveRestore(archive.ID); err != nil {
				t.Fatal(err)
			}
			restored, err := d.GetReverseArtifact(task.ID, artifact.ID)
			if err != nil || restored == nil || restored.SHA256 != artifact.SHA256 {
				t.Fatalf("legacy artifact changed: %+v %v", restored, err)
			}
			for _, table := range nativeCampaignArchiveTables {
				var n int
				if err = d.QueryRow(`SELECT count(*) FROM `+table+` WHERE task_id=$1`, task.ID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("legacy restore invented %s: %d %v", table, n, err)
				}
			}
		})
	}
}

func TestNativeCampaignArchiveRestoreMissingTableAtomic(t *testing.T) {
	d, err := Open(fuzzTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	task, _ := campaignArchiveHistoryFixture(t, d, "paused")
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "missing-table.tar", nativeCampaignHash("missing-table"), 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	claimTaskArchiveFixture(t, d, archive.ID)
	state := func() []byte {
		var raw []byte
		if err := d.QueryRow(`SELECT json_build_object('task',row_to_json(t),'archive',row_to_json(a)) FROM tasks t JOIN task_archives a ON a.task_id=t.id WHERE a.id=$1`, archive.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := state()
	for _, missing := range nativeCampaignArchiveTables {
		t.Run(missing, func(t *testing.T) {
			bad := *snapshot
			bad.Tables = map[string]json.RawMessage{}
			for name, raw := range snapshot.Tables {
				if name != missing {
					bad.Tables[name] = raw
				}
			}
			if _, err := d.RestoreTaskArchive(archive.ID, &bad, 0); err == nil {
				t.Fatal("actual Restore accepted missing table")
			}
			if !bytes.Equal(before, state()) {
				t.Fatal("failed Restore changed task/archive")
			}
			for _, table := range nativeCampaignArchiveTables {
				var n int
				if err := d.QueryRow(`SELECT count(*) FROM `+table+` WHERE task_id=$1`, task.ID).Scan(&n); err != nil || n != 0 {
					t.Fatalf("failed Restore wrote %s: %d %v", table, n, err)
				}
			}
		})
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	if err = d.CompleteTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
}
