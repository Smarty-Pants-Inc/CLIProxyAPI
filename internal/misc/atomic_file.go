package misc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// WriteFileAtomic replaces path with data so readers never observe a partial
// file: it writes a temp file in the same directory with mode perm, fsyncs it,
// and renames it over path. A missing parent directory is created 0700, since
// callers use it for credential material.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("create directory: %w", errMkdir)
	}
	tmp, errCreate := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if errCreate != nil {
		return fmt.Errorf("create temp file: %w", errCreate)
	}
	tmpPath := tmp.Name()
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		if errRemove := os.Remove(tmpPath); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			log.WithError(errRemove).Debug("failed to remove temp file")
		}
	}()
	// CreateTemp already uses 0600; Chmod makes perm exact regardless of umask.
	if errChmod := tmp.Chmod(perm); errChmod != nil {
		return fmt.Errorf("chmod temp file: %w", errChmod)
	}
	if _, errWrite := tmp.Write(data); errWrite != nil {
		return fmt.Errorf("write temp file: %w", errWrite)
	}
	if errSync := tmp.Sync(); errSync != nil {
		return fmt.Errorf("sync temp file: %w", errSync)
	}
	closed = true
	if errClose := tmp.Close(); errClose != nil {
		return fmt.Errorf("close temp file: %w", errClose)
	}
	if errRename := os.Rename(tmpPath, path); errRename != nil {
		return fmt.Errorf("rename temp file: %w", errRename)
	}
	// Best effort: persist the rename itself. Not supported on every platform.
	if d, errOpen := os.Open(dir); errOpen == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
