package logging

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Log roots and spool directories contain raw request bodies.
func ensurePrivateLogDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("request log directory is required")
	}
	dir = filepath.Clean(dir) // do not let a trailing slash hide a root symlink from Lstat
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("request log directory is not a directory: %s", dir)
	}
	return os.Chmod(dir, 0700)
}

// Tighten existing logs at startup, including leftover spool parts. WalkDir does
// not follow symlinks: neither linked files nor linked directories are chmodded.
func tightenRequestLogPermissions(dir string) error {
	if err := ensurePrivateLogDir(dir); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0700)
		}
		if entry.Type().IsRegular() {
			return os.Chmod(path, 0600)
		}
		return nil
	})
}
