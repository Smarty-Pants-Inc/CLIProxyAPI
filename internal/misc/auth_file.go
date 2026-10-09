package misc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// authFileMode is the exact mode of every auth/token file: OAuth tokens are owner-only.
const authFileMode os.FileMode = 0o600

// WriteAuthFileAtomic is the single atomic writer for auth and token files. It
// replaces the file at path with data so that a concurrent reader sees either
// the previous content or the new content, never an empty or partially written
// file. It creates a temp file in the same directory, sets it to exactly 0600
// (independent of umask) before any data is written, writes and fsyncs it,
// closes it, renames it over path and then fsyncs the directory on a
// best-effort basis. The temp file is removed on any error.
//
// The rename replaces path itself: when path is a symlink, the link is replaced
// by a regular file and its target is left untouched. A legacy file with a
// wider mode is replaced by an owner-only one. The parent directory must
// already exist; callers create it 0700.
func WriteAuthFileAtomic(path string, data []byte) (err error) {
	if path == "" {
		return fmt.Errorf("auth file path is empty")
	}
	dir := filepath.Dir(path)
	// ponytail: a short fixed prefix, not the auth file's own name, so a valid name near the
	// filesystem's component-length limit still fits; watchers only react to .json names.
	tmp, err := os.CreateTemp(dir, ".auth-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp auth file: %w", err)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if err == nil {
			return
		}
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpPath)
	}()

	// Exact mode on the open handle before the token bytes land, so the data is
	// never readable with a wider mode.
	if err = tmp.Chmod(authFileMode); err != nil {
		return fmt.Errorf("chmod temp auth file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("write temp auth file: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp auth file: %w", err)
	}
	closed = true
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close temp auth file: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp auth file: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes a directory entry change (the rename) to disk. It is best
// effort: the new content is already in place, and some platforms and
// filesystems cannot fsync a directory, so a failure is logged, not returned.
// Windows cannot fsync a directory handle, so it is skipped there.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, errOpen := os.Open(dir)
	if errOpen != nil {
		log.Debugf("auth file: open directory for fsync failed: %v", errOpen)
		return
	}
	if errSync := d.Sync(); errSync != nil {
		log.Debugf("auth file: directory fsync failed: %v", errSync)
	}
	if errClose := d.Close(); errClose != nil {
		log.Debugf("auth file: close directory failed: %v", errClose)
	}
}
