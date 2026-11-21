package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/Autumn-27/artex/db"
)

// nativeCampaignCheckpointStore is an explicit Linux-local immutable CAS sink.
// Constructing it does not register a service, start a worker or touch the disk.
type nativeCampaignCheckpointStore struct {
	pg   *db.DB
	root string
}

func newNativeCampaignCheckpointStore(pg *db.DB, root string) (*nativeCampaignCheckpointStore, error) {
	if pg == nil || root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("checkpoint store requires DB and an absolute trusted storage root")
	}
	if err := nativeCampaignCASAvailable(); err != nil {
		return nil, err
	}
	return &nativeCampaignCheckpointStore{pg: pg, root: filepath.Clean(root)}, nil
}

func validateNativeCampaignCheckpointCorpus(in nativeCampaignCheckpointWrite) ([]nativeCampaignCheckpointRecord, error) {
	if in.TaskID <= 0 || in.CampaignID <= 0 || in.AttemptID <= 0 || in.Identity.TaskID != in.TaskID || in.Identity.CampaignID != in.CampaignID || in.Identity.AttemptID != in.AttemptID {
		return nil, errors.New("checkpoint corpus identity mismatch")
	}
	if in.Final.FormatVersion != 1 || len(in.Corpus) < 1 || len(in.Corpus) > NativeCampaignMaxCheckpointEntries || in.Final.EntryCount != len(in.Corpus) || in.Final.TotalBytes < 1 || in.Final.TotalBytes > 1<<20 {
		return nil, errors.New("checkpoint corpus count/byte bound mismatch")
	}
	records := append([]nativeCampaignCheckpointRecord(nil), in.Corpus...)
	var total int64
	unique := make(map[string]bool, len(records))
	for _, record := range records {
		if !nativeCampaignCheckpointSourceTypeValid(record.SourceType) {
			return nil, errors.New("invalid checkpoint source type")
		}
		if err := validateNativeCampaignSourceRef(record.SourceRef); err != nil {
			return nil, err
		}
		if len(record.Data) < 1 || len(record.Data) > NativeCampaignMaxObjectBytes || record.Length != len(record.Data) {
			return nil, errors.New("checkpoint object length mismatch")
		}
		total += int64(len(record.Data))
		if total > 1<<20 {
			return nil, errors.New("checkpoint corpus exceeds 1 MiB")
		}
		sum := sha256.Sum256(record.Data)
		if hex.EncodeToString(sum[:]) != record.SHA256 || record.StorageKey != nativeCampaignCheckpointStorageKey(in.TaskID, record.SHA256) {
			return nil, errors.New("checkpoint object hash/key mismatch")
		}
		if unique[record.SHA256] {
			return nil, errors.New("duplicate checkpoint object")
		}
		unique[record.SHA256] = true
	}
	if total != in.Final.TotalBytes {
		return nil, errors.New("checkpoint total bytes mismatch")
	}
	manifest, err := nativeCampaignCanonicalManifest(in.TaskID, in.CampaignID, in.AttemptID, records)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(manifest)
	if hex.EncodeToString(sum[:]) != in.Final.ManifestSHA256 {
		return nil, errors.New("checkpoint manifest hash mismatch")
	}
	sortNativeCampaignCheckpointRecords(records)
	return records, nil
}

func (s *nativeCampaignCheckpointStore) PersistCheckpoint(ctx context.Context, in nativeCampaignCheckpointWrite) (*db.NativeCampaignCheckpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records, err := validateNativeCampaignCheckpointCorpus(in)
	if err != nil {
		return nil, err
	}
	manifest := db.NativeCampaignManifestInput{
		TaskID: in.TaskID, CampaignID: in.CampaignID, AttemptID: in.AttemptID,
		ManifestSHA256: in.Final.ManifestSHA256, EntryCount: len(records), TotalBytes: in.Final.TotalBytes, Truncated: in.Final.Truncated,
	}
	for i, record := range records {
		manifest.Entries = append(manifest.Entries, db.NativeCampaignEntryInput{Ordinal: i, SHA256: record.SHA256, Length: int64(record.Length), StorageKey: record.StorageKey, SourceType: record.SourceType, SourceRef: record.SourceRef})
	}
	var checkpoint *db.NativeCampaignCheckpoint
	// A single task filesystem lock spans physical quota scan, durable publication
	// and SQL commit. A DB failure leaves immutable orphan CAS files, counted by
	// the next scan. Never remove an already-published/reused object on rollback.
	err = persistNativeCampaignCAS(ctx, s.root, in.TaskID, records, func() error {
		var err error
		checkpoint, err = s.pg.CommitVerifiedNativeCampaignCheckpoint(ctx, db.NativeCampaignCheckpointCommit{NativeCampaignLeaseIdentity: in.Identity, Manifest: manifest})
		return err
	})
	if err != nil {
		return nil, err
	}
	return checkpoint, nil
}

const nativeCampaignResumeSelectionRule = "canonical-prefix-v1:max32:max65536"

type nativeCampaignResumeSeed struct {
	SHA256 string `json:"sha256"`
	Length int    `json:"length"`
}
type nativeCampaignResumeObservation struct {
	CheckpointID         int64                      `json:"checkpoint_id"`
	SourceAttemptID      int64                      `json:"source_attempt_id"`
	SourceManifestSHA256 string                     `json:"source_manifest_sha256"`
	SelectionRule        string                     `json:"selection_rule"`
	Selected             []nativeCampaignResumeSeed `json:"selected"`
	OmittedCount         int                        `json:"omitted_count"`
	SourceTruncated      bool                       `json:"source_truncated"`
}
type nativeCampaignCheckpointRestore struct {
	TaskID           int64
	CampaignID       int64
	SourceEntryCount int
	SourceTotalBytes int64
	Seeds            []nativeCampaignSeed
	Observation      nativeCampaignResumeObservation
}

func (r *nativeCampaignCheckpointRestore) validateBinding(taskID, campaignID, checkpointID, newAttemptID int64) error {
	if r == nil || r.TaskID != taskID || r.CampaignID != campaignID || r.Observation.CheckpointID != checkpointID || r.Observation.SourceAttemptID <= 0 || r.Observation.SourceAttemptID == newAttemptID || !db.NativeSHA256(r.Observation.SourceManifestSHA256) || r.Observation.SelectionRule != nativeCampaignResumeSelectionRule {
		return errors.New("restore identity or selection rule mismatch")
	}
	if r.SourceEntryCount < 1 || r.SourceEntryCount > NativeCampaignMaxCheckpointEntries || r.SourceTotalBytes < 1 || r.SourceTotalBytes > 1<<20 || len(r.Seeds) < 1 || len(r.Seeds) > NativeCampaignMaxSeeds || len(r.Observation.Selected) != len(r.Seeds) || r.Observation.OmittedCount != r.SourceEntryCount-len(r.Seeds) || r.Observation.OmittedCount < 0 {
		return errors.New("restore selection bounds mismatch")
	}
	total := 0
	for i, seed := range r.Seeds {
		if !nativeCampaignCheckpointSourceTypeValid(seed.SourceType) {
			return errors.New("invalid restored seed source")
		}
		if err := validateNativeCampaignSourceRef(seed.SourceRef); err != nil {
			return err
		}
		data, err := base64.StdEncoding.Strict().DecodeString(seed.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(data) != seed.DataBase64 || len(data) < 1 || len(data) > NativeCampaignMaxObjectBytes {
			return errors.New("invalid restored seed")
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != seed.SHA256 || r.Observation.Selected[i].SHA256 != seed.SHA256 || r.Observation.Selected[i].Length != len(data) {
			return errors.New("restore seed/proof mismatch")
		}
		total += len(data)
	}
	if total > NativeCampaignMaxSeedBytes || int64(total) > r.SourceTotalBytes {
		return errors.New("restore seed bytes exceed bound")
	}
	return nil
}

func (s *nativeCampaignCheckpointStore) ValidateCheckpoint(ctx context.Context, taskID, campaignID, checkpointID int64) error {
	_, err := s.LoadCheckpoint(ctx, taskID, campaignID, checkpointID)
	return err
}

func (s *nativeCampaignCheckpointStore) LoadCheckpoint(ctx context.Context, taskID, campaignID, checkpointID int64) (*nativeCampaignCheckpointRestore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	campaign, err := s.pg.NativeCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	if campaign.LatestCheckpointID == nil || *campaign.LatestCheckpointID != checkpointID {
		return nil, errors.New("restore checkpoint is not the campaign's latest checkpoint")
	}
	cp, err := s.pg.NativeCampaignCheckpoint(ctx, taskID, checkpointID)
	if err != nil {
		return nil, err
	}
	if cp.TaskID != taskID || cp.CampaignID != campaignID || cp.AttemptID <= 0 || cp.State != "verified" || cp.VerifiedAt == nil || cp.FormatVersion != 1 || cp.EntryCount < 1 || cp.EntryCount > NativeCampaignMaxCheckpointEntries || cp.TotalBytes < 1 || cp.TotalBytes > 1<<20 {
		return nil, errors.New("restore checkpoint is not a verified bounded source")
	}
	manifest, err := s.pg.NativeCampaignManifest(ctx, taskID, cp.ManifestID)
	if err != nil {
		return nil, err
	}
	if manifest.TaskID != taskID || manifest.CampaignID != campaignID || manifest.AttemptID != cp.AttemptID || manifest.FormatVersion != 1 || manifest.EntryCount != cp.EntryCount || manifest.TotalBytes != cp.TotalBytes || manifest.Truncated != cp.Truncated || !db.NativeSHA256(manifest.ManifestSHA256) {
		return nil, errors.New("restore manifest identity/summary mismatch")
	}
	entries, err := s.pg.NativeCampaignEntries(ctx, taskID, manifest.ID)
	if err != nil {
		return nil, err
	}
	if len(entries) != manifest.EntryCount {
		return nil, errors.New("restore entries are incomplete")
	}
	records := make([]nativeCampaignCheckpointRecord, 0, len(entries))
	unique := make(map[string]bool, len(entries))
	var total int64
	for i, entry := range entries {
		// The schema's immutable composite object FK additionally binds each
		// snapshot to (object_id,task,hash,length,key); no per-object SQL loop.
		if entry.TaskID != taskID || entry.ManifestID != manifest.ID || entry.ObjectID <= 0 || entry.Ordinal != i || !db.NativeSHA256(entry.SHA256) || entry.Length < 1 || entry.Length > NativeCampaignMaxObjectBytes || entry.StorageKey != nativeCampaignCheckpointStorageKey(taskID, entry.SHA256) || !nativeCampaignCheckpointSourceTypeValid(entry.SourceType) {
			return nil, errors.New("invalid restore entry identity/metadata")
		}
		if err := validateNativeCampaignSourceRef(entry.SourceRef); err != nil {
			return nil, err
		}
		if unique[entry.SHA256] {
			return nil, errors.New("duplicate restore object")
		}
		unique[entry.SHA256] = true
		total += entry.Length
		if total > 1<<20 {
			return nil, errors.New("restore source exceeds 1 MiB")
		}
		records = append(records, nativeCampaignCheckpointRecord{SHA256: entry.SHA256, Length: int(entry.Length), StorageKey: entry.StorageKey, SourceType: entry.SourceType, SourceRef: entry.SourceRef})
	}
	if total != manifest.TotalBytes {
		return nil, errors.New("restore source byte count mismatch")
	}
	canonical, err := nativeCampaignCanonicalManifest(taskID, campaignID, cp.AttemptID, records)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != manifest.ManifestSHA256 {
		return nil, errors.New("restore source canonical manifest mismatch")
	}
	sortNativeCampaignCheckpointRecords(records)
	restore := &nativeCampaignCheckpointRestore{TaskID: taskID, CampaignID: campaignID, SourceEntryCount: len(records), SourceTotalBytes: total, Observation: nativeCampaignResumeObservation{CheckpointID: checkpointID, SourceAttemptID: cp.AttemptID, SourceManifestSHA256: manifest.ManifestSHA256, SelectionRule: nativeCampaignResumeSelectionRule, SourceTruncated: cp.Truncated}}
	selectedBytes := 0
	selecting := true
	err = readNativeCampaignCAS(ctx, s.root, taskID, records, func(record nativeCampaignCheckpointRecord, data []byte) error {
		// Always verify the whole source, including the unselected tail. Only
		// selection stops at the deterministic prefix budget; verification does not.
		if selecting && (len(restore.Seeds) >= NativeCampaignMaxSeeds || selectedBytes+len(data) > NativeCampaignMaxSeedBytes) {
			selecting = false
		}
		if selecting {
			restore.Seeds = append(restore.Seeds, nativeCampaignSeed{SHA256: record.SHA256, DataBase64: base64.StdEncoding.EncodeToString(data), SourceType: record.SourceType, SourceRef: record.SourceRef})
			restore.Observation.Selected = append(restore.Observation.Selected, nativeCampaignResumeSeed{SHA256: record.SHA256, Length: len(data)})
			selectedBytes += len(data)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	restore.Observation.OmittedCount = len(records) - len(restore.Seeds)
	// Recheck the authoritative source pointer after I/O. The manager also
	// repeats ordinary authorization/fencing immediately before factory/Start.
	current, err := s.pg.NativeCampaign(ctx, taskID, campaignID)
	if err != nil {
		return nil, err
	}
	if current.LatestCheckpointID == nil || *current.LatestCheckpointID != checkpointID {
		return nil, errors.New("restore source changed during verification")
	}
	if err := restore.validateBinding(taskID, campaignID, checkpointID, 0); err != nil {
		return nil, err
	}
	return restore, nil
}
