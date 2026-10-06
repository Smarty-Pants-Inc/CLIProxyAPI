//go:build darwin

package config

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func secureConfigMAC(_ *os.File, path string, original os.FileInfo) error {
	if original == nil {
		return nil
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	return verifyOriginalConfigSecurity(source, original, "Darwin", probeDarwinConfigProtection)
}

func probeDarwinConfigProtection(source *os.File) error {
	info, err := source.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Flags != 0 {
		return fmt.Errorf("original config has unsupported file flags")
	}
	n, err := unix.Flistxattr(int(source.Fd()), nil)
	if err != nil && err != unix.ENOTSUP {
		return fmt.Errorf("inspect original extended attributes: %w", err)
	}
	if n != 0 {
		return fmt.Errorf("original config has unsupported extended attributes")
	}
	// Darwin ACLs are not POSIX ACL xattrs. Inspect the stable descriptor using
	// the native utility, following /dev/fd/3 rather than inspecting a pathname.
	// Any ACE, including a deny, or unexpected output causes a safe refusal.
	cmd := exec.Command("/bin/ls", "-ldeL", "/dev/fd/3")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin"}
	cmd.ExtraFiles = []*os.File{source}
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("inspect original ACL: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "/dev/fd/3") || len(lines[0]) < 11 || lines[0][10] == '+' {
		return fmt.Errorf("original config ACL cannot be reproduced")
	}
	return nil
}
