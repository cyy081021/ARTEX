package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// Explicit local dependencies, not a registration or feature activation.
type nativeCampaignLocalStorage struct{ root string }

func newNativeCampaignLocalStorage(root string) (*nativeCampaignLocalStorage, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return nil, errors.New("absolute trusted campaign storage root required")
	}
	if err := nativeCampaignCASAvailable(); err != nil {
		return nil, err
	}
	return &nativeCampaignLocalStorage{root: filepath.Clean(root)}, nil
}
func (s *nativeCampaignLocalStorage) VerifyArtifact(ctx context.Context, taskID int64, a *db.ReverseArtifact) error {
	if s == nil || a == nil || taskID <= 0 || a.TaskID != taskID || a.SizeBytes < 64 || a.SizeBytes > 64<<20 || len(a.SHA256) != 64 {
		return errors.New("invalid task-bound campaign artifact")
	}
	prefix := fmt.Sprintf("tasks/%d/reverse/artifacts/", taskID)
	if filepath.IsAbs(a.Path) || strings.Contains(a.Path, "\\") || !strings.HasPrefix(a.Path, prefix) || filepath.ToSlash(filepath.Clean(a.Path)) != a.Path {
		return errors.New("artifact path is not a canonical task-relative path")
	}
	data, err := readNativeCampaignArtifact(ctx, s.root, a.Path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if int64(len(data)) != a.SizeBytes || hex.EncodeToString(digest[:]) != a.SHA256 {
		return errors.New("artifact content no longer matches its registered hash/length")
	}
	// Static ELF64/little-endian/x86-64 header check; never execute an artifact.
	if len(data) < 64 || string(data[:4]) != "\x7fELF" || data[4] != 2 || data[5] != 1 || data[6] != 1 || data[18] != 62 || data[19] != 0 {
		return errors.New("campaign requires a Linux x86-64 ELF artifact")
	}
	a.Path = filepath.Join(s.root, filepath.FromSlash(a.Path))
	return nil
}
func (s *nativeCampaignLocalStorage) PersistEvidence(ctx context.Context, in nativeCampaignEvidenceWrite) (*nativeCampaignEvidenceRef, error) {
	if s == nil || in.TaskID <= 0 || in.CampaignID <= 0 || in.AttemptID <= 0 || in.Operation != "native_campaign" || in.Authority != "candidate-only" || in.Kind != "attempt_final" || len(in.Observation) == 0 || len(in.Observation) > 256<<10 {
		return nil, errors.New("invalid candidate-only campaign evidence")
	}
	var observation map[string]json.RawMessage
	if json.Unmarshal(in.Observation, &observation) != nil || observation == nil {
		return nil, errors.New("campaign evidence must be an object")
	}
	raw, err := json.Marshal(map[string]any{"structuredContent": map[string]any{"operation": "native_campaign", "authority": "candidate-only", "task_id": in.TaskID, "campaign_id": in.CampaignID, "attempt_id": in.AttemptID, "kind": in.Kind, "normalized_result": json.RawMessage(in.Observation)}})
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	key := fmt.Sprintf("tasks/%d/reverse/campaigns/%d/evidence/%d-%s.json", in.TaskID, in.CampaignID, in.AttemptID, hash)
	if err = publishNativeCampaignEvidence(ctx, s.root, key, raw); err != nil {
		return nil, err
	}
	return &nativeCampaignEvidenceRef{ResultPath: key, SHA256: hash, Observation: append(json.RawMessage(nil), in.Observation...)}, nil
}
