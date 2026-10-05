//go:build linux

package config

import (
	"bytes"
	"fmt"
	"os"

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
