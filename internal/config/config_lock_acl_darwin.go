//go:build darwin

package config

import (
	"fmt"
	"os"
	"os/exec"
)

func restrictConfigLockACL(file *os.File) error {
	cmd := exec.Command("/bin/chmod", "-N", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restrict publication lock ACL: %w", err)
	}
	return nil
}
