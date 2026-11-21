package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// All paths are administrator configuration, never profile/spec/frame input.
// The first implementation deliberately supports one local Linux namespace and
// one fixed local daemon, not arbitrary bridges, remote contexts or mappings.
type nativeCampaignEnvironmentConfig struct{ Python, ModuleRoot, Docker, StagingRoot, DockerConfigDir string }
type nativeCampaignEnvironment struct {
	config  nativeCampaignEnvironmentConfig
	starter nativeCampaignProcessStarter
}

const nativeCampaignBootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('scripts.native_runner.campaign_entry',run_name='__main__')"

func newNativeCampaignEnvironment(c nativeCampaignEnvironmentConfig) (*nativeCampaignEnvironment, error) {
	for _, p := range []string{c.Python, c.ModuleRoot, c.Docker, c.StagingRoot, c.DockerConfigDir} {
		if !filepath.IsAbs(p) || strings.ContainsAny(p, "\x00\r\n") {
			return nil, errors.New("explicit absolute campaign environment paths required")
		}
	}
	checked, err := validateNativeCampaignEnvironmentPaths(c)
	if err != nil {
		return nil, err
	}
	return &nativeCampaignEnvironment{config: checked, starter: defaultNativeCampaignProcessStarter}, nil
}
func (e *nativeCampaignEnvironment) environment() []string {
	return append(nativeCampaignProcessDefaultEnv(), "DOCKER_HOST=unix:///var/run/docker.sock", "DOCKER_CONFIG="+e.config.DockerConfigDir)
}
func (e *nativeCampaignEnvironment) processConfig() nativeCampaignProcessConfig {
	return nativeCampaignProcessConfig{Command: []string{e.config.Python, "-I", "-S", "-B", "-c", nativeCampaignBootstrap, e.config.ModuleRoot, "--docker", e.config.Docker, "--staging-root", e.config.StagingRoot, "--docker-config", e.config.DockerConfigDir}, Dir: e.config.ModuleRoot, Env: e.environment()}
}
func (e *nativeCampaignEnvironment) ResolveImageID(ctx context.Context, p reverseRuntimeProfile, digest string) (string, error) {
	if e == nil || p.Platform != "linux" || p.Engine != "docker-native" || len(p.PathMappings) != 0 || !db.NativeImageDigest(digest) {
		return "", errors.New("campaign environment requires a local Linux profile without path mappings and a pinned image")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, startErr := e.starter(nativeCampaignProcessSpec{Argv: []string{e.config.Docker, "image", "inspect", "--format", "{{.Id}}", digest}, Dir: e.config.ModuleRoot, Env: e.environment()})
	if h == nil {
		return "", fmt.Errorf("image inspect could not start: %v", startErr)
	}
	var closeOnce, killOnce sync.Once
	closeHandle := func() { closeOnce.Do(func() { _ = h.Close() }) }
	kill := func() { killOnce.Do(func() { _ = h.Kill() }) }
	finished, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			kill()
			closeHandle()
		case <-finished:
		}
	}()
	defer func() { close(finished); <-watchDone; closeHandle() }()
	if startErr != nil || ctx.Err() != nil {
		kill()
		closeHandle()
		_ = h.Wait()
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", startErr
	}
	if h.Stdin() != nil {
		_ = h.Stdin().Close()
	}
	type output struct {
		data []byte
		err  error
	}
	read := func(reader io.Reader, ch chan<- output) {
		if reader == nil {
			ch <- output{err: errors.New("image inspect stream missing")}
			return
		}
		data, err := io.ReadAll(io.LimitReader(reader, 4097))
		if len(data) > 4096 {
			err = errors.New("image inspect output limit")
			kill()
			closeHandle()
		}
		ch <- output{data, err}
	}
	out, diagnostic := make(chan output, 1), make(chan output, 1)
	go read(h.Stdout(), out)
	go read(h.Stderr(), diagnostic)
	stdout, stderr := <-out, <-diagnostic
	waitErr := h.Wait()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if stdout.err != nil || stderr.err != nil || waitErr != nil || len(stderr.data) != 0 {
		return "", errors.New("image inspect did not return bounded clean success")
	}
	id := strings.TrimSuffix(string(stdout.data), "\n")
	if !validResolvedImageID(id) {
		return "", errors.New("image inspect must return one complete immutable id")
	}
	return id, nil
}
