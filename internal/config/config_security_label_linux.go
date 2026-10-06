//go:build linux

package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Preserve the original mandatory-access boundary before any credentials are staged.
func secureConfigMAC(staging *os.File, path string, original os.FileInfo) error {
	if original == nil {
		return nil
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	// Inspect the original ACL on this stable descriptor, under the publication
	// lock and before writing credentials. Extended ACL mode group bits are a
	// mask, not authorization for the owning group. We do not copy ACLs, so
	// refuse rather than widen a grant or silently discard a legitimate reader.
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect original config identity: %w", err)
	}
	if !os.SameFile(original, info) {
		return fmt.Errorf("original config identity changed before ACL inspection")
	}
	n, err := unix.Fgetxattr(int(source.Fd()), "system.posix_acl_access", nil)
	if err != nil && err != unix.ENODATA && err != unix.ENOTSUP {
		return fmt.Errorf("inspect original POSIX ACL: %w", err)
	}
	if err == nil || n > 0 {
		return fmt.Errorf("publication refused: original POSIX ACL cannot be preserved exactly")
	}
	// Enumerate both boundaries. Absence of SELinux alone does not rule out
	// Smack or another mandatory policy on the original or staging inode.
	for _, boundary := range []struct {
		name string
		file *os.File
	}{{"original", source}, {"staging", staging}} {
		n, err = unix.Flistxattr(int(boundary.file.Fd()), nil)
		if err != nil && err != unix.ENOTSUP {
			return fmt.Errorf("inspect %s security attributes: %w", boundary.name, err)
		}
		if n > 0 {
			raw := make([]byte, n)
			n, err = unix.Flistxattr(int(boundary.file.Fd()), raw)
			if err != nil {
				return fmt.Errorf("read %s security attributes: %w", boundary.name, err)
			}
			if err = refuseUnsupportedConfigAttributes(strings.Split(string(raw[:n]), "\x00"), "security.selinux"); err != nil {
				return fmt.Errorf("publication refused: %s: %w", boundary.name, err)
			}
		}
	}
	return preserveSELinuxLabel(
		func() ([]byte, error) { return configSELinuxLabel(source) },
		func() ([]byte, error) { return configSELinuxLabel(staging) },
		func(label []byte) error { return unix.Fsetxattr(int(staging.Fd()), "security.selinux", label, 0) },
	)
}

func configSELinuxLabel(file *os.File) ([]byte, error) {
	n, err := unix.Fgetxattr(int(file.Fd()), "security.selinux", nil)
	if err == unix.ENODATA || err == unix.ENOTSUP {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	label := make([]byte, n)
	n, err = unix.Fgetxattr(int(file.Fd()), "security.selinux", label)
	if err != nil {
		return nil, err
	}
	return label[:n], nil
}

func preserveSELinuxLabel(readOriginal, readStaging func() ([]byte, error), writeStaging func([]byte) error) error {
	original, err := readOriginal()
	if err != nil {
		return fmt.Errorf("inspect original SELinux label: %w", err)
	}
	staging, err := readStaging()
	if err != nil {
		return fmt.Errorf("inspect staging SELinux label: %w", err)
	}
	if bytes.Equal(original, staging) {
		return nil
	}
	// Do not remove a staging label to imitate an unlabeled destination: that
	// requires a policy decision we cannot safely infer from a missing attribute.
	if len(original) == 0 {
		return fmt.Errorf("cannot preserve unlabeled config boundary")
	}
	if err = writeStaging(original); err != nil {
		return fmt.Errorf("preserve config SELinux label: %w", err)
	}
	staging, err = readStaging()
	if err != nil || !bytes.Equal(original, staging) {
		return fmt.Errorf("cannot verify preserved config SELinux label")
	}
	return nil
}
