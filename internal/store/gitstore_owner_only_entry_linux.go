//go:build linux

package store

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func enforceOwnerOnlyEntry(parentFD int, parentPath, name string, _ bool) (errResult error) {
	path := filepath.Join(parentPath, name)
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
	// O_PATH pins the entry without opening it for data access. In
	// particular, a device or FIFO swapped in after Fstatat is harmless.
	fd, errOpen := openNoFollow(parentFD, name, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if errOpen != nil {
		if errors.Is(errOpen, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("open path handle %s: %w", path, errOpen)
	}
	defer func() {
		if errClose := unix.Close(fd); errClose != nil && errResult == nil {
			errResult = fmt.Errorf("close path handle %s: %w", path, errClose)
		}
	}()
	var stat unix.Stat_t
	if errStat := unix.Fstat(fd, &stat); errStat != nil {
		return fmt.Errorf("stat path handle %s: %w", path, errStat)
	}
	if stat.Mode&unix.S_IFMT != before.Mode&unix.S_IFMT || stat.Dev != before.Dev || stat.Ino != before.Ino {
		return nil
	}
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		// Reopen only the pinned, confirmed directory. There is no
		// ENOTDIR fallback to a data open of the original entry name.
		dirFD, errDir := openNoFollow(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
		if errDir != nil {
			return fmt.Errorf("open pinned directory %s: %w", path, errDir)
		}
		var dirStat unix.Stat_t
		if errStat := unix.Fstat(dirFD, &dirStat); errStat != nil {
			_ = unix.Close(dirFD)
			return fmt.Errorf("stat pinned directory %s: %w", path, errStat)
		}
		if dirStat.Mode&unix.S_IFMT != unix.S_IFDIR || dirStat.Dev != stat.Dev || dirStat.Ino != stat.Ino {
			_ = unix.Close(dirFD)
			return nil
		}
		return enforceOwnerOnlyDirFD(dirFD, path)
	case unix.S_IFREG:
		if uint32(stat.Mode)&0o7777 == 0o600 {
			return nil
		}
		// fchmod cannot operate on O_PATH. Follow only this process's
		// descriptor link, which refers to the pinned inode, not its name.
		if errMode := unix.Fchmodat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", fd), 0o600, 0); errMode != nil {
			return fmt.Errorf("chmod pinned file %s to 0600: %w", path, errMode)
		}
	}
	return nil
}
