//go:build !linux

package server

import "errors"

func validateNativeCampaignEnvironmentPaths(c nativeCampaignEnvironmentConfig) (nativeCampaignEnvironmentConfig, error) {
	return c, errors.New("campaign environment requires Linux")
}
