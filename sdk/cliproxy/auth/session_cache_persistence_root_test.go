package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// fakeAuthDirEntries lists everything written under the fake auth-dir.
func fakeAuthDirEntries(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	errWalk := filepath.WalkDir(dir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir && path != filepath.Join(dir, "state") {
			found = append(found, path)
		}
		return nil
	})
	if errWalk != nil {
		t.Fatal(errWalk)
	}
	return found
}

// P2 (round 3): after EnablePersistence the state directory is pinned. Swapping
// its parent for a symlink into auth-dir cannot redirect a save; the snapshot
// lands in the pinned directory.
func TestSessionCachePersistencePinsDirectoryAgainstParentSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	fakeAuth := filepath.Join(root, "auth")
	for _, dir := range []string{filepath.Join(parent, "state"), filepath.Join(fakeAuth, "state")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cache := newPersistenceTestCache(t, 100)
	if err := cache.EnablePersistence(filepath.Join(parent, "state", "session-affinity.state")); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved")
	if err := os.Rename(parent, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fakeAuth, parent); err != nil {
		t.Fatal(err)
	}
	cache.Set("session", "auth")
	if found := fakeAuthDirEntries(t, fakeAuth); len(found) != 0 {
		t.Fatalf("save wrote under auth-dir: %v", found)
	}
	if err := cache.PersistenceError(); err != nil {
		t.Fatalf("save to the pinned directory failed: %v", err)
	}
	if got := readPersistenceTestState(t, filepath.Join(moved, "state", "session-affinity.state")); len(got.Groups) != 1 {
		t.Fatalf("pinned directory snapshot: %+v", got)
	}
}

// P2 (round 3): a parent flipping between the realDir directory and a symlink into
// auth-dir while saves run must never let a temp or final file reach auth-dir.
// Pathname re-checks only narrow this window; the pinned root closes it.
func TestSessionCachePersistenceRacingParentSwapNeverWritesAuthDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlinks need privileges on Windows")
	}
	root := t.TempDir()
	realDir := filepath.Join(root, "realDir")
	fakeAuth := filepath.Join(root, "auth")
	for _, dir := range []string{filepath.Join(realDir, "state"), filepath.Join(fakeAuth, "state")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	parent := filepath.Join(root, "parent")
	link := filepath.Join(root, "parent.tmp")
	point := func(target string) {
		_ = os.Remove(link)
		if err := os.Symlink(target, link); err == nil {
			_ = os.Rename(link, parent)
		}
	}
	path := filepath.Join(parent, "state", "session-affinity.state")
	deadline := time.Now().Add(3 * time.Second)
	for trial := 0; trial < 400 && time.Now().Before(deadline); trial++ {
		point(realDir)
		_ = os.Remove(filepath.Join(realDir, "state", "session-affinity.state"))
		cache := newPersistenceTestCache(t, 100)
		if err := cache.EnablePersistence(path); err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if i%2 == 0 {
					point(fakeAuth)
				} else {
					point(realDir)
				}
			}
		}()
		for i := 0; i < 20; i++ {
			cache.Set("session", []string{"a", "b"}[i%2])
		}
		close(stop)
		wg.Wait()
		if found := fakeAuthDirEntries(t, fakeAuth); len(found) != 0 {
			t.Fatalf("trial %d: save wrote under auth-dir: %v", trial, found)
		}
	}
}
