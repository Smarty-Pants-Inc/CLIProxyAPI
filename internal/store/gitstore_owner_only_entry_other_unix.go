//go:build unix && !linux

package store

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func enforceOwnerOnlyEntry(parentFD int, parentPath, name string, hintDir bool) error {
	path := filepath.Join(parentPath, name)
	// Type()==0 can mean an unknown type, not just a regular file. Never open
	// an entry until a no-follow stat confirms it is safe to open.
	var before unix.Stat_t
	if errStat := unix.Fstatat(parentFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); errStat != nil {
		if errors.Is(errStat, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, errStat)
	}
	switch before.Mode & unix.S_IFMT {
	case unix.S_IFDIR, unix.S_IFREG:
	default:
		return nil
	}
	if ownerOnlyWalkBeforeOpen != nil {
		ownerOnlyWalkBeforeOpen(parentPath, name)
	}
	fileFlags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC
	flags := fileFlags
	if hintDir {
		flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	}
	fd, errOpen := openNoFollow(parentFD, name, flags)
	if errors.Is(errOpen, unix.ENOTDIR) && hintDir {
		// Replaced by a non-directory since the listing; take its true type.
		fd, errOpen = openNoFollow(parentFD, name, fileFlags)
	}
	if errOpen != nil {
		if errors.Is(errOpen, unix.ENOENT) || ownerOnlySkippable(parentFD, name) {
			return nil
		}
		return fmt.Errorf("open %s: %w", path, errOpen)
	}
	var stat unix.Stat_t
	if errStat := unix.Fstat(fd, &stat); errStat != nil {
		_ = unix.Close(fd)
		return fmt.Errorf("stat %s: %w", path, errStat)
	}
	if stat.Mode&unix.S_IFMT != before.Mode&unix.S_IFMT || stat.Dev != before.Dev || stat.Ino != before.Ino {
		// The entry was swapped after Fstatat; do not change the replacement.
		_ = unix.Close(fd)
		return nil
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return enforceOwnerOnlyDirFD(fd, path)
	case unix.S_IFREG:
		errMode := fchmodOwnerOnly(fd, path, 0o600)
		if errClose := unix.Close(fd); errClose != nil && errMode == nil {
			errMode = fmt.Errorf("close %s: %w", path, errClose)
		}
		return errMode
	default:
		_ = unix.Close(fd)
		return nil
	}
}
