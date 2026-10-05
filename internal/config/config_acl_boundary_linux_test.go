//go:build linux

package config

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func configBoundaryDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "config-acl-boundary-")
	if err != nil {
		t.Fatal(err)
	}
	// Retain fixtures, including refused private staging, for diagnosis.
	return dir
}

func configBoundaryACL(entries [][3]uint32) []byte {
	raw := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(raw, 2)
	for i, entry := range entries {
		off := 4 + 8*i
		binary.LittleEndian.PutUint16(raw[off:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(raw[off+2:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(raw[off+4:], entry[2])
	}
	return raw
}

func configBoundaryGroupRead(t *testing.T, path string) uint16 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	n, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	if err == unix.ENODATA || err == unix.ENOTSUP {
		return uint16(info.Mode().Perm()>>3) & 4
	}
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, n)
	if _, err = unix.Getxattr(path, "system.posix_acl_access", raw); err != nil {
		t.Fatal(err)
	}
	group, mask := uint16(0), uint16(7)
	for off := 4; off+8 <= len(raw); off += 8 {
		tag, permission := binary.LittleEndian.Uint16(raw[off:]), binary.LittleEndian.Uint16(raw[off+2:])
		if tag == 4 {
			group = permission
		}
		if tag == 16 {
			mask = permission
		}
	}
	return group & mask & 4
}

// Extended ACL group mode bits are the mask, not the owning group's grant.
// Refuse publication unless every original effective ACL permission is preserved.
func TestOriginalACLGroupBoundaryRefusesPublication(t *testing.T) {
	dir := configBoundaryDir(t)
	path := filepath.Join(dir, "config.yaml")
	original := []byte("debug: false\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	acl := configBoundaryACL([][3]uint32{{1, 6, 0xffffffff}, {2, 4, 60001}, {4, 0, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}})
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0640 || configBoundaryGroupRead(t, path) != 0 {
		t.Fatal("invalid original ACL boundary fixture")
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AtomicWriteConfigCAS(path, []byte("debug: true\n"), version)
	if err == nil {
		t.Fatal("publication must refuse an original ACL it cannot preserve exactly")
	}
	if !strings.Contains(err.Error(), "original POSIX ACL") {
		t.Fatalf("unclear refusal: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatalf("refusal changed original bytes: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || configBoundaryGroupRead(t, path) != 0 {
		t.Fatal("refusal changed original inode/access")
	}
	actual := make([]byte, len(acl))
	if n, err := unix.Getxattr(path, "system.posix_acl_access", actual); err != nil || n != len(acl) || !bytes.Equal(actual, acl) {
		t.Fatalf("refusal changed original ACL: %v", err)
	}
	t.Log("publication refused; original bytes, inode and complete ACL retained")
}
