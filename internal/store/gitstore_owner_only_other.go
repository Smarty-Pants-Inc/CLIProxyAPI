//go:build !unix

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// enforceOwnerOnlyTree (non-Unix fallback) makes root and every directory below it 0700 and every
// regular file 0600. Symlinks are neither followed nor changed (a symlinked
// root is left alone), so a link cannot redirect the chmod outside the tree.
// A missing root is not an error.
func enforceOwnerOnlyTree(root string) error {
	rootInfo, errStat := os.Lstat(root)
	if errors.Is(errStat, fs.ErrNotExist) {
		return nil
	}
	if errStat != nil {
		return errStat
	}
	if !rootInfo.IsDir() {
		return nil
	}
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, errWalk error) error {
		if errWalk != nil {
			return errWalk
		}
		var want fs.FileMode
		switch {
		case entry.Type()&fs.ModeSymlink != 0:
			return nil
		case entry.IsDir():
			want = 0o700
		case entry.Type().IsRegular():
			want = 0o600
		default:
			return nil
		}
		info, errInfo := entry.Info()
		if errInfo != nil {
			return errInfo
		}
		if info.Mode().Perm() == want {
			return nil
		}
		if errChmod := os.Chmod(path, want); errChmod != nil {
			return fmt.Errorf("chmod %s to %#o: %w", path, want, errChmod)
		}
		return nil
	})
}
