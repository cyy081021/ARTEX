//go:build !linux

package server

import (
	"context"
	"errors"
)

func nativeCampaignCASAvailable() error {
	return errors.New("native campaign checkpoint storage requires Linux no-follow and no-replace filesystem semantics")
}
func persistNativeCampaignCAS(context.Context, string, int64, []nativeCampaignCheckpointRecord, func() error) error {
	return nativeCampaignCASAvailable()
}

func readNativeCampaignCAS(context.Context, string, int64, []nativeCampaignCheckpointRecord, func(nativeCampaignCheckpointRecord, []byte) error) error {
	return nativeCampaignCASAvailable()
}
