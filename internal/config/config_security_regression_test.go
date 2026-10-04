//go:build linux

package config

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A directory default ACL must never make the replacement readable to a named user.
func TestPublicationNeverWidensAccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Linux POSIX ACL: owner rwx, named nobody r, group r, mask r, other none.
	acl := make([]byte, 4+5*8)
	binary.LittleEndian.PutUint32(acl, 2)
	entries := [][3]uint32{{1, 7, 0xffffffff}, {2, 4, 65534}, {4, 4, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}}
	for i, e := range entries {
		off := 4 + i*8
		binary.LittleEndian.PutUint16(acl[off:], uint16(e[0]))
		binary.LittleEndian.PutUint16(acl[off+2:], uint16(e[1]))
		binary.LittleEndian.PutUint32(acl[off+4:], e[2])
	}
	if err := unix.Setxattr(dir, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteConfigCAS(path, []byte("debug: true\n"), version); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	oldStat, newStat := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if oldStat.Uid != newStat.Uid || oldStat.Gid != newStat.Gid {
		t.Fatalf("ownership changed: %v -> %v", oldStat, newStat)
	}
	if after.Mode().Perm()&0077 != 0 {
		t.Fatalf("replacement grants ACL/group/other access: %o", after.Mode().Perm())
	}
	n, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	if err != nil && err != unix.ENODATA {
		t.Fatal(err)
	}
	if n > 0 {
		raw := make([]byte, n)
		if _, err := unix.Getxattr(path, "system.posix_acl_access", raw); err != nil {
			t.Fatal(err)
		}
		for off := 4; off+8 <= len(raw); off += 8 {
			if binary.LittleEndian.Uint16(raw[off:]) == 16 && binary.LittleEndian.Uint16(raw[off+2:]) != 0 {
				t.Fatal("inherited named ACL is effective")
			}
		}
	}
}

func TestNewConfigIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := AtomicWriteConfig(path, []byte("api-keys: [secret]\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("new config mode=%o", info.Mode().Perm())
	}
}
