//go:build linux || darwin

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Retain fixtures: this test deliberately registers no cleanup hook.
func TestRestrictedGroupReadSurvivesPublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-group-read-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte("debug: false\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AtomicWriteConfigCAS(path, []byte("debug: true\n"), version); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0640 {
		t.Fatalf("restricted group read lost: mode=%04o, want 0640", after.Mode().Perm())
	}
	oldStat, newStat := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if oldStat.Uid != newStat.Uid || oldStat.Gid != newStat.Gid {
		t.Fatalf("owner/group changed: %d:%d -> %d:%d", oldStat.Uid, oldStat.Gid, newStat.Uid, newStat.Gid)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "debug: true\n" {
		t.Fatalf("publication: %q %v", data, err)
	}
}
