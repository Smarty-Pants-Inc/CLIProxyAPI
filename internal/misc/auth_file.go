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
// file. Before any data is written, it creates a private temp file in the same
// directory: exactly 0600 on POSIX, or a protected current-user-only DACL on
// Windows. On Windows it also restricts the parent directory before staging.
// It writes and fsyncs the temp file, closes it, renames it over path and then
// fsyncs the directory on a best-effort basis. The temp file is removed on any error.
//
// The rename replaces path itself: when path is a symlink, the link is replaced
// by a regular file and its target is left untouched. A legacy file with a
// wider mode or DACL is replaced by an owner-only one. The parent directory
// must already exist; callers create it 0700 on POSIX.
func WriteAuthFileAtomic(path string, data []byte) (err error) {
	if path == "" {
		return fmt.Errorf("auth file path is empty")
	}
	dir := filepath.Dir(path)
	if err = RestrictAuthDir(dir); err != nil {
		return fmt.Errorf("restrict auth directory: %w", err)
	}
	tmp, err := createPrivateAuthTemp(dir)
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
