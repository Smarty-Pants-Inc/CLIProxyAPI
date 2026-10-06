//go:build linux || darwin

package config

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func openConfigFileLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// Cooperating privileged and host writers use the config owner's private lock.
// The inode is never replaced, including when another writer holds it.
func secureConfigLockIdentity(file *os.File, original os.FileInfo) error {
	current, err := file.Stat()
	if err != nil {
		return err
	}
	lockOwner, ok := current.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect publication lock owner")
	}
	if !current.Mode().IsRegular() || lockOwner.Nlink != 1 {
		return fmt.Errorf("publication lock must be a single-link regular file")
	}
	// Validate the pathname and link identity before any privileged repair.
	pathInfo, errPath := os.Lstat(file.Name())
	if errPath != nil || !os.SameFile(current, pathInfo) {
		return fmt.Errorf("publication lock identity changed before repair")
	}
	if original == nil {
		if lockOwner.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("unexpected publication lock owner")
		}
		if err := restrictConfigLockACL(file); err != nil {
			return err
		}
		return file.Chmod(0600)
	}
	owner, ok := original.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect config owner for publication lock")
	}
	if lockOwner.Uid != owner.Uid && lockOwner.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unexpected publication lock owner")
	}
	if err := restrictConfigLockACL(file); err != nil {
		return err
	}
	if err := preserveConfigLockOwner(owner.Uid, owner.Gid, lockOwner.Uid, lockOwner.Gid, file.Chown); err != nil {
		return err
	}
	// Config read-only bits do not govern this separate coordination inode.
	return file.Chmod(0600)
}

func preserveConfigLockOwner(uid, gid, currentUID, currentGID uint32, chown func(int, int) error) error {
	if uid == currentUID && gid == currentGID {
		return nil
	}
	if err := chown(int(uid), int(gid)); err != nil {
		return fmt.Errorf("preserve config-owner publication lock: %w", err)
	}
	return nil
}
