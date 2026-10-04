//go:build !windows

package config

import (
	"fmt"
	"os"
	"syscall"
)

func secureConfigReplacement(file *os.File, original os.FileInfo) error {
	if original != nil {
		stat, ok := original.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot preserve config ownership")
		}
		current, err := file.Stat()
		if err != nil {
			return err
		}
		own, ok := current.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot inspect staging ownership")
		}
		if own.Uid != stat.Uid || own.Gid != stat.Gid {
			if err := file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				return fmt.Errorf("preserve config ownership: %w", err)
			}
		}
	}
	// Also masks all inherited POSIX named-user/group ACL entries to no access.
	return file.Chmod(0600)
}
