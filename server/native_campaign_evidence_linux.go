//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func nativeCampaignStorageRoot(root string) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, errors.New("invalid trusted campaign storage root")
	}
	fd, err := unix.Open("/", nativeCampaignDirFlags, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	fs := nativeCampaignCAS{syncDir: unix.Fsync}
	base, err := fs.openDirs(fd, strings.Split(strings.TrimPrefix(root, "/"), "/"), false, false)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(int(base.Fd()), &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0022 != 0 {
		base.Close()
		return nil, errors.New("campaign storage root is not owner-controlled")
	}
	return base, nil
}
func nativeCampaignReadBoundedFile(ctx context.Context, dir *os.File, name string, max int64, private bool) ([]byte, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, errors.New("invalid campaign file component")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "campaign-file")
	defer f.Close()
	var before, after unix.Stat_t
	if err = unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	mask := uint32(0022)
	if private {
		mask = 0077
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Mode&mask != 0 || before.Size < 1 || before.Size > max {
		return nil, errors.New("campaign file is not a bounded owned regular file")
	}
	var data bytes.Buffer
	buf := make([]byte, 32<<10)
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			if int64(data.Len()+n) > max {
				return nil, errors.New("campaign file exceeded size bound")
			}
			data.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}
	if err = unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || int64(data.Len()) != before.Size {
		return nil, errors.New("campaign file changed while reading")
	}
	return data.Bytes(), ctx.Err()
}
func readNativeCampaignArtifact(ctx context.Context, root, key string) ([]byte, error) {
	return readNativeCampaignOwnedFile(ctx, root, key, 64<<20)
}
func readNativeCampaignOwnedFile(ctx context.Context, root, key string, maxBytes int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base, err := nativeCampaignStorageRoot(root)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	fs := nativeCampaignCAS{syncDir: unix.Fsync}
	dir, err := fs.openDirs(int(base.Fd()), strings.Split(filepath.ToSlash(filepath.Dir(key)), "/"), false, false, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	return nativeCampaignReadBoundedFile(ctx, dir, filepath.Base(key), maxBytes, false)
}
func publishNativeCampaignEvidence(ctx context.Context, root, key string, data []byte) error {
	return (nativeCampaignCAS{syncDir: unix.Fsync}).publishEvidence(ctx, root, key, data)
}

func (fs nativeCampaignCAS) publishEvidence(ctx context.Context, root, key string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 512<<10 {
		return errors.New("campaign evidence exceeds bound")
	}
	base, err := nativeCampaignStorageRoot(root)
	if err != nil {
		return err
	}
	defer base.Close()
	parts := strings.Split(filepath.ToSlash(filepath.Dir(key)), "/")
	parent, err := fs.openDirs(int(base.Fd()), parts[:len(parts)-1], true, false)
	if err != nil {
		return err
	}
	defer parent.Close()
	dir, err := fs.openDirs(int(parent.Fd()), parts[len(parts)-1:], true, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := filepath.Base(key)
	if existing, err := nativeCampaignReadBoundedFile(ctx, dir, name, 512<<10, true); err == nil {
		if !bytes.Equal(existing, data) {
			return errors.New("immutable evidence content conflict")
		}
		if err := fs.syncDir(int(dir.Fd())); err != nil {
			return err
		}
		return ctx.Err()
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := ".partial-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(dir.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(int(dir.Fd()), tmp, 0)
	f := os.NewFile(uintptr(fd), "campaign-evidence-partial")
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = unix.Renameat2(int(dir.Fd()), tmp, int(dir.Fd()), name, unix.RENAME_NOREPLACE)
	if errors.Is(err, unix.EEXIST) {
		existing, readErr := nativeCampaignReadBoundedFile(ctx, dir, name, 512<<10, true)
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return errors.New("immutable evidence race conflict")
		}
	} else if err != nil {
		return err
	}
	if err = fs.syncDir(int(dir.Fd())); err != nil {
		return err
	}
	return ctx.Err()
}
