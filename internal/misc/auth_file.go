package misc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteAuthFileAtomic replaces the auth file at path with data so that a
// concurrent reader sees either the previous content or the new content, never
// an empty or partially written file. It writes a temp file in the same
// directory, fsyncs and closes it, sets mode 0600, renames it over path and then
// fsyncs the directory. The temp file is removed on any error.
//
// The rename replaces path itself: when path is a symlink, the link is replaced
// by a regular file and its target is left untouched. The parent directory must
// already exist.
func WriteAuthFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
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
	if err = os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp auth file: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp auth file: %w", err)
	}
	return syncDir(dir)
}

// syncDir flushes a directory entry change (the rename) to disk. Windows cannot
// fsync a directory handle, so it is skipped there.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, errOpen := os.Open(dir)
	if errOpen != nil {
		return fmt.Errorf("open auth directory: %w", errOpen)
	}
	errSync := d.Sync()
	errClose := d.Close()
	if errSync != nil {
		return fmt.Errorf("sync auth directory: %w", errSync)
	}
	if errClose != nil {
		return fmt.Errorf("close auth directory: %w", errClose)
	}
	return nil
}
