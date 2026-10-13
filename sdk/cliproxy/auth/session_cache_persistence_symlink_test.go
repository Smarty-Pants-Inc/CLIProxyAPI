package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// A symlink planted after EnablePersistence must not redirect later saves.
func TestSessionCachePersistenceRefusesSymlinkedDirectoryAfterEnable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	for _, existing := range []bool{false, true} {
		name := "missing"
		if existing {
			name = "existing"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "state")
			other := filepath.Join(root, "other")
			if err := os.Mkdir(other, 0o700); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			cache := newPersistenceTestCache(t, 100)
			if err := cache.EnablePersistence(filepath.Join(dir, "session-affinity.state")); err != nil {
				t.Fatal(err)
			}
			// EnablePersistence creates and pins a missing directory too.
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, dir); err != nil {
				t.Fatal(err)
			}
			cache.Set("session", "auth")
			if cache.PersistenceError() == nil {
				t.Fatal("save through a planted directory symlink did not fail closed")
			}
			if entries, err := os.ReadDir(other); err != nil || len(entries) != 0 {
				t.Fatalf("save redirected through symlink: %v, %v", entries, err)
			}
		})
	}
}

// Saves replace a symlinked state file with a private regular file; the link
// target is never written.
func TestSessionCachePersistenceReplacesSymlinkedStateFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file symlinks need privileges on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	writePersistenceTestState(t, target, sessionCacheRecord{AuthID: "one", ExpiresAt: time.Now().Add(time.Hour), Aliases: []string{"a"}})
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "session-affinity.state")
	// os.Root follows only relative links that stay inside the state directory.
	if err := os.Symlink(filepath.Base(target), path); err != nil {
		t.Fatal(err)
	}
	cache := newPersistenceTestCache(t, 100)
	if err := cache.EnablePersistence(path); err != nil {
		t.Fatal(err)
	}
	cache.Set("b", "two")
	if err := cache.PersistenceError(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatalf("symlink target was written: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file not replaced by a private regular file: %v, %v", info, err)
	}
}
