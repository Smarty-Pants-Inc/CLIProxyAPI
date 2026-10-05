package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// P3: the renamed snapshot and any directory created for it are durable only
// after their parent directories are synced. Sync runs after the rename, and a
// sync failure is the sticky persistence error that fails closed.
func TestSessionCachePersistenceSyncsDirectoriesAfterRename(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "new", "state", "sessions.json")
	var synced []string
	restore := sessionCacheSyncDir
	t.Cleanup(func() { sessionCacheSyncDir = restore })
	sessionCacheSyncDir = func(dir string) error {
		if dir == filepath.Dir(path) {
			if _, err := os.Stat(path); err != nil {
				t.Errorf("directory synced before the rename: %v", err)
			}
		}
		synced = append(synced, dir)
		return restore(dir)
	}
	cache := newPersistenceTestCache(t, 100)
	if err := cache.EnablePersistence(path); err != nil {
		t.Fatal(err)
	}
	cache.Set("conversation", "account-one")
	if err := cache.PersistenceError(); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{filepath.Dir(path): true, filepath.Join(root, "new"): true, root: true}
	for _, dir := range synced {
		delete(want, dir)
	}
	if len(want) != 0 {
		t.Fatalf("directories not synced: %v (synced %v)", want, synced)
	}

	synced = nil
	cache.Set("conversation-2", "account-one")
	if len(synced) != 1 || synced[0] != filepath.Dir(path) {
		t.Fatalf("existing directory: synced %v, want only the parent", synced)
	}

	sessionCacheSyncDir = func(string) error { return errors.New("sync failed") }
	cache.Set("conversation-3", "account-one")
	errSave := cache.PersistenceError()
	if errSave == nil {
		t.Fatal("directory sync failure was not reported")
	}
	sessionCacheSyncDir = restore
	cache.Set("conversation-4", "account-one")
	if cache.PersistenceError() != errSave {
		t.Fatal("directory sync failure was not sticky")
	}
}
