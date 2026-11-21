package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/Autumn-27/artex/db"
	"path/filepath"
)

// Validate the final staged/extracted payload, not a previously checked live
// source. All retained references, including prepared evidence, must exist.
func verifyNativeCampaignArchiveFiles(ctx context.Context, payload string, snapshot *db.TaskArchiveSnapshot) error {
	refs, err := db.NativeCampaignArchiveFiles(snapshot)
	if err != nil {
		return err
	}
	for _, ref := range refs {
		data, err := readNativeCampaignOwnedFile(ctx, filepath.Join(payload, "files"), ref.Path, ref.MaxBytes)
		if err != nil {
			return errors.New("Campaign archive contains a missing or unsafe retained file reference")
		}
		sum := sha256.Sum256(data)
		if (ref.Length > 0 && int64(len(data)) != ref.Length) || hex.EncodeToString(sum[:]) != ref.SHA256 {
			return errors.New("Campaign archive retained file hash or length mismatch")
		}
	}
	return ctx.Err()
}
