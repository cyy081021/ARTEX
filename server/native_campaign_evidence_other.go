//go:build !linux

package server

import (
	"context"
	"errors"
)

func readNativeCampaignArtifact(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("campaign local storage requires Linux")
}
func publishNativeCampaignEvidence(context.Context, string, string, []byte) error {
	return errors.New("campaign local storage requires Linux")
}

func readNativeCampaignOwnedFile(context.Context, string, string, int64) ([]byte, error) {
	return nil, errors.New("Campaign archive file verification requires Linux")
}
