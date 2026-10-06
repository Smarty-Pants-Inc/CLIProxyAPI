//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRound4RepeatedInheritedACLRefusalCleansCandidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("api-keys: [fixture-original]\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	entries := [][3]uint32{{1, 7, 0xffffffff}, {2, 4, 60001}, {4, 4, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}}
	if err := unix.Setxattr(dir, "system.posix_acl_default", configBoundaryACL(entries), 0); err != nil {
		t.Fatal(err)
	}
	version, _ := ConfigFileVersion(path)
	for i := 0; i < 12; i++ {
		if _, err := AtomicWriteConfigCAS(path, []byte("api-keys: [fixture-candidate]\n"), version); err == nil {
			t.Fatal("late inherited ACL refusal accepted")
		}
	}
	after, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	current, _ := ConfigFileVersion(path)
	if !os.SameFile(before, after) || string(raw) != string(original) || version != current {
		t.Fatal("late refusals changed original")
	}
	candidates, _ := filepath.Glob(filepath.Join(dir, ".config-*.tmp"))
	if len(candidates) != 0 {
		t.Fatalf("late refusals retained %d credential-bearing candidates", len(candidates))
	}
	lock, err := os.Stat(path + ".lock")
	if err != nil || !lock.Mode().IsRegular() {
		t.Fatal("cleanup removed shared lock")
	}
}

func TestRound4CleanupDoesNotUnlinkSubstitutedPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	var substituted string
	err := atomicWriteConfigWithRename(path, []byte("candidate"), func(from, to string) error {
		substituted = from
		if err := os.Rename(from, from+".owned"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(from, []byte("not transaction owned"), 0600); err != nil {
			t.Fatal(err)
		}
		return os.ErrPermission
	})
	if err == nil {
		t.Fatal("refusal accepted")
	}
	raw, err := os.ReadFile(substituted)
	if err != nil || string(raw) != "not transaction owned" {
		t.Fatal("cleanup deleted substituted staging path")
	}
}
