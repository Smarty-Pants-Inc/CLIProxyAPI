//go:build darwin

package config

import (
	"fmt"
	"os"
	"os/exec"
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
			if err = file.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
				return fmt.Errorf("preserve config ownership: %w", err)
			}
		}
	}
	// Darwin chmod mode bits do not mask inherited ACL entries. Use the native
	// ACL utility on the open descriptor, not a mutable staging pathname, before
	// writing any credentials. Failure refuses publication, retaining the target.
	cmd := exec.Command("/bin/chmod", "-N", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restrict staging Darwin ACL: %w", err)
	}
	return file.Chmod(0600)
}

func preserveConfigReadAccess(file *os.File, original os.FileInfo) error {
	return file.Chmod(replacementConfigMode(original, false))
}
