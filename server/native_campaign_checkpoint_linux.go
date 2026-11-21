//go:build linux

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const nativeCampaignCASObjects = 16384
const nativeCampaignCASBytes int64 = 512 << 20
const nativeCampaignDirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC

func nativeCampaignCASAvailable() error { return nil }

// Per-call syscall seam for deterministic durability-failure tests, not shared
// mutable hooks or an additional ownership/quota ledger.
type nativeCampaignCAS struct {
	syncDir    func(int) error
	createFile func(int, string, int, uint32) (int, error) // per-call fault seam, default Openat
}

// Every directory is opened relative to a held descriptor, never by a checked
// string subsequently reopened. The trusted configured root must already exist.
func (fs nativeCampaignCAS) openDirs(parent int, parts []string, create, private bool, requireOwner ...bool) (*os.File, error) {
	fd, err := unix.Openat(parent, ".", nativeCampaignDirFlags, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.Contains(part, "/") {
			unix.Close(fd)
			return nil, errors.New("invalid checkpoint directory component")
		}
		next, openErr := unix.Openat(fd, part, nativeCampaignDirFlags, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return nil, err
			}
			next, openErr = unix.Openat(fd, part, nativeCampaignDirFlags, 0)
		}
		if openErr == nil && create {
			// Also sync an existing name: a previous mkdir may have succeeded
			// before its parent sync failed. A retry must close that window.
			if err := fs.syncDir(fd); err != nil {
				unix.Close(next)
				unix.Close(fd)
				return nil, err
			}
		}
		unix.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
		if create || private || (len(requireOwner) > 0 && requireOwner[0]) {
			var st unix.Stat_t
			if err := unix.Fstat(fd, &st); err != nil {
				unix.Close(fd)
				return nil, err
			}
			mask := uint32(0022)
			if private {
				mask = 0077
			}
			if st.Uid != uint32(os.Geteuid()) || st.Mode&mask != 0 {
				unix.Close(fd)
				return nil, errors.New("checkpoint directory is writable by another principal")
			}
		}
	}
	return os.NewFile(uintptr(fd), "campaign-directory"), nil
}

func nativeCampaignCheckFile(st *unix.Stat_t, allowEmpty bool) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Mode&0077 != 0 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("checkpoint object is not a private single-link regular file")
	}
	if st.Size < 0 || (!allowEmpty && st.Size == 0) || st.Size > NativeCampaignMaxObjectBytes {
		return errors.New("checkpoint object size exceeds bound")
	}
	return nil
}

func nativeCampaignReadCAS(bucket *os.File, name string, record nativeCampaignCheckpointRecord) error {
	_, err := nativeCampaignReadCASBytes(bucket, name, record)
	return err
}

func nativeCampaignReadCASBytes(bucket *os.File, name string, record nativeCampaignCheckpointRecord) ([]byte, error) {
	fd, err := unix.Openat(int(bucket.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "campaign-object")
	defer f.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if err := nativeCampaignCheckFile(&before, false); err != nil {
		return nil, err
	}
	if before.Size != int64(record.Length) {
		return nil, errors.New("stored checkpoint object length mismatch")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(record.Length)+1))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	if len(data) != record.Length || hex.EncodeToString(sum[:]) != record.SHA256 {
		return nil, errors.New("stored checkpoint object hash mismatch")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if err := nativeCampaignCheckFile(&after, false); err != nil {
		return nil, err
	}
	if before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("checkpoint object changed during verification")
	}
	return data, nil
}

// Physical accounting includes published orphans and old partial files. It
// never treats a bounded/truncated scan as proof that quota remains available.
func (fs nativeCampaignCAS) scan(ctx context.Context, root *os.File) (map[string]bool, int, int64, error) {
	existing := make(map[string]bool)
	count := 0
	var total int64
	directories := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, 0, err
		}
		entries, err := root.ReadDir(64)
		if err != nil && err != io.EOF {
			return nil, 0, 0, err
		}
		for _, entry := range entries {
			directories++
			prefix := entry.Name()
			if directories > 256 || len(prefix) != 2 || !strings.Contains("0123456789abcdef", prefix[:1]) || !strings.Contains("0123456789abcdef", prefix[1:]) {
				return nil, 0, 0, errors.New("invalid/excessive checkpoint CAS directory")
			}
			bucket, err := fs.openDirs(int(root.Fd()), []string{prefix}, false, true)
			if err != nil {
				return nil, 0, 0, err
			}
			scanErr := func() error {
				defer bucket.Close()
				for {
					if err := ctx.Err(); err != nil {
						return err
					}
					files, err := bucket.ReadDir(64)
					if err != nil && err != io.EOF {
						return err
					}
					for _, file := range files {
						count++
						if count > nativeCampaignCASObjects {
							return nativeCampaignAuthErr("quota_exceeded", 413, "checkpoint physical object quota exceeded")
						}
						name := file.Name()
						partial := strings.HasPrefix(name, ".partial-")
						if !partial && (len(name) != 64 || !strings.HasPrefix(name, prefix)) {
							return errors.New("invalid checkpoint CAS filename")
						}
						if !partial {
							if _, err := hex.DecodeString(name); err != nil || strings.ToLower(name) != name {
								return errors.New("invalid checkpoint CAS hash")
							}
						}
						var st unix.Stat_t
						if err := unix.Fstatat(int(bucket.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
							return err
						}
						if err := nativeCampaignCheckFile(&st, partial); err != nil {
							return err
						}
						total += st.Size
						if total > nativeCampaignCASBytes {
							return nativeCampaignAuthErr("quota_exceeded", 413, "checkpoint physical byte quota exceeded")
						}
						if !partial {
							existing[name] = true
						}
					}
					if err == io.EOF {
						return nil
					}
				}
			}()
			if scanErr != nil {
				return nil, 0, 0, scanErr
			}
		}
		if err == io.EOF {
			return existing, count, total, nil
		}
	}
}

func (fs nativeCampaignCAS) publish(ctx context.Context, root *os.File, record nativeCampaignCheckpointRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	bucket, err := fs.openDirs(int(root.Fd()), []string{record.SHA256[:2]}, true, true)
	if err != nil {
		return err
	}
	defer bucket.Close()
	if err := nativeCampaignReadCAS(bucket, record.SHA256, record); err == nil {
		// Reusing a file is not evidence that an earlier rename's directory
		// sync succeeded. Confirm durability before allowing any DB commit.
		return fs.syncDir(int(bucket.Fd()))
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	partial := ".partial-" + hex.EncodeToString(nonce[:])
	createFile := fs.createFile
	if createFile == nil {
		createFile = unix.Openat
	}
	fd, err := createFile(int(bucket.Fd()), partial, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "campaign-partial")
	// This uniquely created partial is the only path ever deleted here. Published
	// objects are immutable and remain even if a later DB commit fails.
	defer func() { f.Close(); unix.Unlinkat(int(bucket.Fd()), partial, 0) }()
	if n, err := f.Write(record.Data); err != nil {
		return err
	} else if n != len(record.Data) {
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = unix.Renameat2(int(bucket.Fd()), partial, int(bucket.Fd()), record.SHA256, unix.RENAME_NOREPLACE)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("checkpoint filesystem lacks safe no-replace publication: %w", err)
	}
	if errors.Is(err, unix.EEXIST) {
		if err := unix.Unlinkat(int(bucket.Fd()), partial, 0); err != nil {
			return err
		}
	}
	if err := fs.syncDir(int(bucket.Fd())); err != nil {
		return err
	}
	return nativeCampaignReadCAS(bucket, record.SHA256, record)
}

func persistNativeCampaignCAS(ctx context.Context, rootPath string, taskID int64, records []nativeCampaignCheckpointRecord, commit func() error) error {
	return (nativeCampaignCAS{syncDir: unix.Fsync}).persist(ctx, rootPath, taskID, records, commit)
}

func (fs nativeCampaignCAS) persist(ctx context.Context, rootPath string, taskID int64, records []nativeCampaignCheckpointRecord, commit func() error) (err error) {
	defer func() {
		if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) {
			err = errors.Join(nativeCampaignAuthErr("quota_exceeded", 413, "checkpoint storage capacity exhausted"), err)
		}
	}()
	if taskID <= 0 || len(records) < 1 || len(records) > NativeCampaignMaxCheckpointEntries || commit == nil {
		return errors.New("invalid checkpoint persistence request")
	}
	return fs.withTask(ctx, rootPath, taskID, true, func(cas *os.File) error {
		existing, count, total, err := fs.scan(ctx, cas)
		if err != nil {
			return err
		}
		for _, record := range records {
			if len(record.SHA256) != 64 || record.Length < 1 || record.Length > NativeCampaignMaxObjectBytes || len(record.Data) != record.Length {
				return errors.New("invalid bounded CAS record")
			}
			if !existing[record.SHA256] {
				count++
				total += int64(record.Length)
				existing[record.SHA256] = true
			}
		}
		if count > nativeCampaignCASObjects || total > nativeCampaignCASBytes {
			return nativeCampaignAuthErr("quota_exceeded", 413, "checkpoint physical quota exceeded")
		}
		for _, record := range records {
			if err := fs.publish(ctx, cas, record); err != nil {
				return err
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return commit()
	})
}

// Restore opens only an existing namespace/lock, and never creates directories,
// objects or a replacement lock file. Shared flock protects a complete read.
func (fs nativeCampaignCAS) withTask(ctx context.Context, rootPath string, taskID int64, create bool, operation func(*os.File) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if taskID <= 0 || operation == nil {
		return errors.New("invalid checkpoint task access")
	}
	if !filepath.IsAbs(rootPath) || filepath.Clean(rootPath) == "/" {
		return errors.New("invalid configured checkpoint root")
	}
	baseFD, err := unix.Open("/", nativeCampaignDirFlags, 0)
	if err != nil {
		return err
	}
	configured, err := fs.openDirs(baseFD, strings.Split(strings.TrimPrefix(filepath.Clean(rootPath), "/"), "/"), false, false)
	unix.Close(baseFD)
	if err != nil {
		return err
	}
	defer configured.Close()
	var configuredStat unix.Stat_t
	if err := unix.Fstat(int(configured.Fd()), &configuredStat); err != nil {
		return err
	}
	if configuredStat.Uid != uint32(os.Geteuid()) || configuredStat.Mode&0022 != 0 {
		return errors.New("checkpoint root is not privately controlled")
	}
	task, err := fs.openDirs(int(configured.Fd()), []string{"tasks", fmt.Sprint(taskID), "reverse", "campaigns"}, create, false)
	if err != nil {
		return err
	}
	defer task.Close()
	var taskStat unix.Stat_t
	if err := unix.Fstat(int(task.Fd()), &taskStat); err != nil {
		return err
	}
	if taskStat.Mode&0077 != 0 || taskStat.Uid != uint32(os.Geteuid()) {
		return errors.New("checkpoint task directory must have mode 0700")
	}
	lockFlags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	lockMode := unix.LOCK_SH
	if create {
		lockFlags = unix.O_RDWR | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		lockMode = unix.LOCK_EX
	}
	lockFD, err := unix.Openat(int(task.Fd()), ".checkpoint.lock", lockFlags, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(lockFD)
	var lockStat unix.Stat_t
	if err := unix.Fstat(lockFD, &lockStat); err != nil {
		return err
	}
	if err := nativeCampaignCheckFile(&lockStat, true); err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = unix.Flock(lockFD, lockMode|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer unix.Flock(lockFD, unix.LOCK_UN)
	cas, err := fs.openDirs(int(task.Fd()), []string{"objects", "sha256"}, create, true)
	if err != nil {
		return err
	}
	defer cas.Close()
	return operation(cas)
}

func readNativeCampaignCAS(ctx context.Context, rootPath string, taskID int64, records []nativeCampaignCheckpointRecord, consume func(nativeCampaignCheckpointRecord, []byte) error) error {
	if len(records) < 1 || len(records) > NativeCampaignMaxCheckpointEntries || consume == nil {
		return errors.New("invalid bounded restore corpus")
	}
	fs := nativeCampaignCAS{syncDir: unix.Fsync}
	return fs.withTask(ctx, rootPath, taskID, false, func(cas *os.File) error {
		for _, record := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(record.SHA256) != 64 {
				return errors.New("invalid restore hash")
			}
			bucket, err := fs.openDirs(int(cas.Fd()), []string{record.SHA256[:2]}, false, true)
			if err != nil {
				return err
			}
			data, err := nativeCampaignReadCASBytes(bucket, record.SHA256, record)
			bucket.Close()
			if err != nil {
				return err
			}
			if err := consume(record, data); err != nil {
				return err
			}
		}
		return ctx.Err()
	})
}
