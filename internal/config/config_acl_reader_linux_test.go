//go:build linux

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// An authorized owning-group reader must survive publication, or the complete
// original must remain live. Inherited named grants must never become effective.
func TestInheritedACLRestrictedGroupSurvivesOrRefuses(t *testing.T) {
	dir := configBoundaryDir(t)
	path := filepath.Join(dir, "config.yaml")
	original := []byte("debug: false\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if configBoundaryGroupRead(t, path) != 4 {
		t.Fatal("original group reader absent")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	entries := [][3]uint32{{1, 7, 0xffffffff}, {2, 4, 60001}, {4, 4, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}}
	if err := unix.Setxattr(dir, "system.posix_acl_default", configBoundaryACL(entries), 0); err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = AtomicWriteConfigCAS(path, []byte("debug: true\n"), version)
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if err != nil {
		if !strings.Contains(err.Error(), "restricted group reader") {
			t.Fatalf("unclear refusal: %v", err)
		}
		after, errStat := os.Stat(path)
		if errStat != nil || !os.SameFile(before, after) || !bytes.Equal(raw, original) || configBoundaryGroupRead(t, path) != 4 {
			t.Fatal("refusal changed original bytes/inode/access")
		}
		t.Logf("publication refused safely: %v", err)
		return
	}
	if configBoundaryGroupRead(t, path) != 4 {
		t.Fatal("successful publication removed an authorized owning-group reader")
	}
	n, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	if err == unix.ENODATA {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	acl := make([]byte, n)
	if _, err = unix.Getxattr(path, "system.posix_acl_access", acl); err != nil {
		t.Fatal(err)
	}
	// A successful implementation may strip inherited entries, but must not
	// enable them. This repair intentionally refuses instead.
	if !bytes.Equal(acl, configBoundaryACL([][3]uint32{{1, 6, 0xffffffff}, {4, 4, 0xffffffff}, {32, 0, 0xffffffff}})) {
		t.Fatal("successful publication did not prove unrelated named grants absent")
	}
}
