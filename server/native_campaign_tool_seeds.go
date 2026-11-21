package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// normalizeCampaignToolSeeds makes the tool tolerant about the seed digest and strict about
// the bytes: a caller may omit sha256 and have it computed, but a supplied digest must match
// its own base64 payload. Without this the service answers a bare "invalid_request", which
// tells an agent nothing about which seed is wrong.
func normalizeCampaignToolSeeds(seeds []nativeCampaignSeed) ([]nativeCampaignSeed, error) {
	out := make([]nativeCampaignSeed, 0, len(seeds))
	for i, seed := range seeds {
		data, err := base64.StdEncoding.Strict().DecodeString(seed.DataBase64)
		if err != nil || base64.StdEncoding.EncodeToString(data) != seed.DataBase64 {
			return nil, fmt.Errorf("seed[%d] data_base64 is not canonical base64", i)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("seed[%d] is empty", i)
		}
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if seed.SHA256 == "" {
			seed.SHA256 = digest
		} else if seed.SHA256 != digest {
			return nil, fmt.Errorf("seed[%d] sha256 does not match its bytes (expected %s)", i, digest)
		}
		out = append(out, nativeCampaignSeed{
			SHA256: seed.SHA256, DataBase64: seed.DataBase64,
			SourceType: seed.SourceType, SourceRef: seed.SourceRef,
		})
	}
	return out, nil
}
