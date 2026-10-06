//go:build linux

package config

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func preserveConfigReadAccess(file *os.File, original os.FileInfo) error {
	// chmod(0600) at staging masks any inherited named entries. Do not unmask
	// them merely to restore the original owning group's read bit.
	n, err := unix.Fgetxattr(int(file.Fd()), "system.posix_acl_access", nil)
	named := false
	if err != nil && err != unix.ENODATA && err != unix.ENOTSUP {
		return fmt.Errorf("inspect staging ACL: %w", err)
	}
	if err == nil && n > 0 {
		raw := make([]byte, n)
		n, err = unix.Fgetxattr(int(file.Fd()), "system.posix_acl_access", raw)
		if err != nil {
			return fmt.Errorf("read staging ACL: %w", err)
		}
		raw = raw[:n]
		if len(raw) < 4 || (len(raw)-4)%8 != 0 || binary.LittleEndian.Uint32(raw) != 2 {
			return fmt.Errorf("invalid staging POSIX ACL")
		}
		for off := 4; off < len(raw); off += 8 {
			tag := binary.LittleEndian.Uint16(raw[off:])
			if tag == 2 || tag == 8 {
				named = true
			}
		}
	}
	if named && original != nil && original.Mode().Perm()&0040 != 0 {
		return fmt.Errorf("publication refused: cannot preserve restricted group reader without enabling inherited named POSIX ACL grants")
	}
	return file.Chmod(replacementConfigMode(original, named))
}
