//go:build unix

package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ownerOnlyWalkBeforeOpen, when set by tests, runs right before an entry is
// opened, after the no-follow stat, so a test can swap the entry during the walk.
var ownerOnlyWalkBeforeOpen func(dirPath, name string)

// enforceOwnerOnlyTree makes root and every directory below it 0700 and every
// regular file 0600. It never changes a mode by path: each entry is opened
// relative to its already-opened parent directory with O_NOFOLLOW, after a
// no-follow stat confirms a regular file or directory. The opened descriptor's
// type, device and inode must match that stat, and the mode is changed
// with fchmod on that descriptor. Symlinks (including one swapped in during
// the walk) are never followed or changed, and anything other than a
// directory or regular file is skipped. A symlinked or non-directory root is
// left alone, and a missing root is not an error.
func enforceOwnerOnlyTree(root string) error {
	fd, errOpen := openNoFollow(unix.AT_FDCWD, root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if errOpen != nil {
		if errors.Is(errOpen, unix.ENOENT) || errors.Is(errOpen, unix.ENOTDIR) || ownerOnlySkippable(unix.AT_FDCWD, root) {
			return nil
		}
		return fmt.Errorf("open %s: %w", root, errOpen)
	}
	return enforceOwnerOnlyDirFD(fd, root)
}

// enforceOwnerOnlyDirFD restricts the directory open as fd (it takes ownership
// of fd) and everything below it.
func enforceOwnerOnlyDirFD(fd int, dirPath string) error {
	dir := os.NewFile(uintptr(fd), dirPath)
	defer func() { _ = dir.Close() }()
	if errMode := fchmodOwnerOnly(fd, dirPath, 0o700); errMode != nil {
		return errMode
	}
	entries, errRead := dir.ReadDir(-1)
	if errRead != nil {
		return fmt.Errorf("read directory %s: %w", dirPath, errRead)
	}
	for _, entry := range entries {
		hint := entry.Type()
		// The directory entry type is only a hint; the opened descriptor is
		// authoritative. Entries hinted as symlinks or special files are never
		// opened (opening a device or FIFO can have side effects).
		if hint&fs.ModeSymlink != 0 || (hint != 0 && !hint.IsDir()) {
			continue
		}
		if errEntry := enforceOwnerOnlyEntry(fd, dirPath, entry.Name(), hint.IsDir()); errEntry != nil {
			return errEntry
		}
	}
	return nil
}

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

// fchmodOwnerOnly sets want on the open descriptor fd when its permission
// bits differ.
func fchmodOwnerOnly(fd int, path string, want uint32) error {
	var stat unix.Stat_t
	if errStat := unix.Fstat(fd, &stat); errStat != nil {
		return fmt.Errorf("stat %s: %w", path, errStat)
	}
	if uint32(stat.Mode)&0o7777 == want {
		return nil
	}
	if errChmod := unix.Fchmod(fd, want); errChmod != nil {
		return fmt.Errorf("chmod %s to %#o: %w", path, want, errChmod)
	}
	return nil
}

func openNoFollow(dirFD int, name string, flags int) (int, error) {
	for {
		fd, errOpen := unix.Openat(dirFD, name, flags, 0)
		if errors.Is(errOpen, unix.EINTR) {
			continue
		}
		return fd, errOpen
	}
}

// ownerOnlySkippable decides whether a failed no-follow open is an entry the
// walk must leave alone: a symlink (O_NOFOLLOW reports ELOOP, EMLINK or EFTYPE
// depending on the platform), something that is not a directory or regular
// file, or an entry that vanished. It inspects the entry without following it.
func ownerOnlySkippable(dirFD int, name string) bool {
	var stat unix.Stat_t
	errStat := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(errStat, unix.ENOENT) {
		return true
	}
	if errStat != nil {
		return false
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR, unix.S_IFREG:
		return false
	default:
		return true
	}
}
