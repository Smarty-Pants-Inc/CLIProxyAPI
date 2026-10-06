//go:build linux

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigLockOwnerBothWriterOrders(t *testing.T) {
	for _, first := range []string{"container", "host"} {
		t.Run(first, func(t *testing.T) {
			const hostUID, hostGID uint32 = 1001, 1002
			uid, gid := hostUID, hostGID
			if first == "container" {
				uid, gid = 0, 0
			}
			chown := func(newUID, newGID int) error { uid, gid = uint32(newUID), uint32(newGID); return nil }
			if err := preserveConfigLockOwner(hostUID, hostGID, uid, gid, chown); err != nil {
				t.Fatal(err)
			}
			if uid != hostUID || gid != hostGID {
				t.Fatal("first writer changed coordination identity/inode")
			}
			if err := preserveConfigLockOwner(hostUID, hostGID, uid, gid, func(int, int) error { t.Error("second writer changed existing owner"); return nil }); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := preserveConfigLockOwner(1001, 1002, 0, 0, func(int, int) error { return errors.New("not permitted") }); err == nil {
		t.Fatal("unpreservable lock owner accepted")
	}
}

func TestConfigLockRefusesLinkedIdentityRepair(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			other := filepath.Join(dir, "other.yaml")
			if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(other, []byte("unchanged\n"), 0640); err != nil {
				t.Fatal(err)
			}
			var err error
			if kind == "symlink" {
				err = os.Symlink(other, path+".lock")
			} else {
				err = os.Link(other, path+".lock")
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := withConfigFileLock(path, func(string) error { t.Error("linked lock accepted"); return nil }); err == nil {
				t.Error("linked lock identity repair not refused")
			}
			info, err := os.Stat(other)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0640 {
				t.Error("lock identity repair changed another file")
			}
		})
	}
}

func TestConfigPublicationLockRemainsOwnerPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := withConfigFileLock(path, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		t.Fatalf("lock inode/mode changed insecurely: %o", after.Mode().Perm())
	}
}
