//go:build linux

package server

import (
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func validateNativeCampaignEnvironmentPaths(c nativeCampaignEnvironmentConfig) (nativeCampaignEnvironmentConfig, error) {
	executable := func(p string) (string, error) {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return "", err
		}
		var st unix.Stat_t
		if err = unix.Lstat(resolved, &st); err != nil {
			return "", err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Mode&0111 == 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return "", errors.New("campaign executable is not administrator-controlled")
		}
		return resolved, nil
	}
	var err error
	if c.Python, err = executable(c.Python); err != nil {
		return c, err
	}
	if c.Docker, err = executable(c.Docker); err != nil {
		return c, err
	}
	for _, item := range []struct {
		path    string
		private bool
	}{{c.ModuleRoot, false}, {c.StagingRoot, true}, {c.DockerConfigDir, true}} {
		f, err := nativeCampaignStorageRoot(filepath.Clean(item.path))
		if err != nil {
			return c, err
		}
		var st unix.Stat_t
		err = unix.Fstat(int(f.Fd()), &st)
		f.Close()
		if err != nil {
			return c, err
		}
		if item.private && st.Mode&0077 != 0 {
			return c, errors.New("campaign staging/config roots must be private")
		}
	}
	// Isolated mode is not package integrity. Validate the bounded source-only
	// deployment, including package initializers; reject bytecode/native caches.
	if err = validateNativeCampaignPackage(c.ModuleRoot); err != nil {
		return c, err
	}
	for _, pair := range [][2]string{{c.StagingRoot, c.DockerConfigDir}, {c.DockerConfigDir, c.StagingRoot}} {
		relative, relErr := filepath.Rel(pair[0], pair[1])
		if relErr != nil || relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			return c, errors.New("campaign staging and Docker config directories must not overlap")
		}
	}
	f, err := os.Open(c.DockerConfigDir)
	if err != nil {
		return c, err
	}
	entries, readErr := f.ReadDir(1)
	f.Close()
	if len(entries) != 0 || readErr != io.EOF {
		return c, errors.New("campaign Docker config directory must be empty")
	}
	c.ModuleRoot = filepath.Clean(c.ModuleRoot)
	c.StagingRoot = filepath.Clean(c.StagingRoot)
	c.DockerConfigDir = filepath.Clean(c.DockerConfigDir)
	return c, nil
}

func validateNativeCampaignPackage(root string) error {
	base, err := nativeCampaignStorageRoot(root)
	if err != nil {
		return err
	}
	defer base.Close()
	// Only expose a dedicated package deployment to sys.path, not a checkout or
	// data directory that could shadow stdlib modules such as argparse/json.
	top, readErr := base.ReadDir(2)
	if (readErr != nil && readErr != io.EOF) || len(top) != 1 || top[0].Name() != "scripts" {
		return errors.New("campaign module root must contain only the scripts package")
	}
	fs := nativeCampaignCAS{syncDir: unix.Fsync}
	scripts, err := fs.openDirs(int(base.Fd()), []string{"scripts"}, false, false, true)
	if err != nil {
		return err
	}
	defer scripts.Close()
	runner, err := fs.openDirs(int(scripts.Fd()), []string{"native_runner"}, false, false, true)
	if err != nil {
		return err
	}
	defer runner.Close()
	foundEntry := false
	for index, dir := range []*os.File{scripts, runner} {
		count := 0
		for {
			entries, readErr := dir.ReadDir(32)
			for _, entry := range entries {
				count++
				if count > 128 {
					return errors.New("campaign package entry limit exceeded")
				}
				name := entry.Name()
				var st unix.Stat_t
				if err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				if index == 0 && name == "native_runner" {
					continue
				}
				if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0022 != 0 || st.Nlink != 1 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
					return errors.New("campaign package contains an untrusted file/directory")
				}
				// Python may prefer native or cached modules even with -B. Use a simple
				// source-only deployment rather than a second cache-integrity ledger.
				if strings.HasSuffix(name, ".pyc") || strings.HasSuffix(name, ".pyo") || strings.HasSuffix(name, ".so") || strings.HasSuffix(name, ".pyd") {
					return errors.New("campaign package must be source-only")
				}
				if index == 1 && name == "campaign_entry.py" {
					foundEntry = true
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
	}
	if !foundEntry {
		return errors.New("campaign package entry is missing")
	}
	return nil
}
