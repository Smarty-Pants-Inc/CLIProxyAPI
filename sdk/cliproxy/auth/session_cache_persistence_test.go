package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newPersistenceTestCache(t *testing.T, capacity int) *SessionCache {
	t.Helper()
	cache := NewSessionCacheWithCapacity(6*time.Hour, capacity)
	// These tests drive cleanup explicitly rather than waiting for a ticker.
	cache.Stop()
	return cache
}

func writePersistenceTestState(t *testing.T, path string, groups ...sessionCacheRecord) {
	t.Helper()
	data, errMarshal := json.Marshal(sessionCacheFile{Version: 1, Groups: groups})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

func readPersistenceTestState(t *testing.T, path string) sessionCacheFile {
	t.Helper()
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var state sessionCacheFile
	if errDecode := json.Unmarshal(data, &state); errDecode != nil {
		t.Fatal(errDecode)
	}
	if state.Version != 1 {
		t.Fatalf("snapshot version = %d", state.Version)
	}
	return state
}

func TestSessionCacheProtectedRegistrationPublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.Set("conversation", "one")
	for _, digest := range []string{"compaction::first", "compaction::second", "compaction::first"} {
		if errSet := cache.SetProtectedAliases("one", digest); errSet != nil {
			t.Fatal(errSet)
		}
		// This is the first published snapshot after registration, with no
		// separate Protect call. A process cut here must already be safe.
		state := readPersistenceTestState(t, path)
		found := false
		for _, group := range state.Groups {
			if hasCompactionSessionAlias(group.Aliases) {
				if !group.Protected || group.AuthID != "one" || len(group.Aliases) != 1 {
					t.Fatal("published signer is unprotected, migrated, or merged")
				}
				found = found || group.Aliases[0] == digest
			}
		}
		if !found {
			t.Fatal("successful registration missing from snapshot")
		}
		restarted := newPersistenceTestCache(t, 100)
		if errEnable := restarted.EnablePersistence(path); errEnable != nil {
			t.Fatal(errEnable)
		}
		restarted.Set("conversation", "two")
		restarted.SetAliases("two", digest, "wrong-account")
		if authID, ok := restarted.Get(digest); !ok || authID != "one" || !restarted.IsProtected(digest) {
			t.Fatal("crash/reload allowed signer account migration")
		}
		if authID, ok := restarted.Get("conversation"); !ok || authID != "two" {
			t.Fatal("independent unprotected routing group could not rebind")
		}
		if _, ok := restarted.Get("wrong-account"); ok {
			t.Fatal("conflicting alias merge partially applied")
		}
	}
}

func TestSessionCacheProtectedRegistrationExistingAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.SetAliases("one", "a", "b")
	if errSet := cache.SetProtectedAliases("one", "b", "c"); errSet != nil {
		t.Fatal(errSet)
	}
	state := readPersistenceTestState(t, path)
	if len(state.Groups) != 1 || !state.Groups[0].Protected || len(state.Groups[0].Aliases) != 3 {
		t.Fatal("existing alias merge was not published protected")
	}
	for _, alias := range []string{"a", "b", "c"} {
		if !cache.IsProtected(alias) {
			t.Fatal("existing group lost protection")
		}
	}
	// Even a legacy caller must not publish a new compaction key unprotected.
	cache.SetAliases("one", "compaction::legacy-caller")
	for _, group := range readPersistenceTestState(t, path).Groups {
		if hasCompactionSessionAlias(group.Aliases) && !group.Protected {
			t.Fatal("SetAliases published an unprotected signer")
		}
	}
}

func TestSessionCacheLegacyCompactionRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	expiry := time.Now().Add(time.Hour)
	writePersistenceTestState(t, path,
		sessionCacheRecord{AuthID: "one", ExpiresAt: expiry, Aliases: []string{"conversation", "compaction::legacy"}},
		sessionCacheRecord{AuthID: "one", ExpiresAt: expiry, Aliases: []string{"ordinary", "ordinary-alias"}},
	)
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	for _, alias := range []string{"conversation", "compaction::legacy"} {
		if !cache.IsProtected(alias) || !cache.entries[alias].expiresAt.Equal(expiry) {
			t.Fatal("legacy signer group not conservatively protected with original expiry")
		}
	}
	if cache.IsProtected("ordinary") {
		t.Fatal("legacy recovery protected an ordinary group")
	}
	cache.SetAliases("two", "conversation", "wrong-account")
	cache.InvalidateAuth("one")
	if cache.CompareAndDelete("conversation", "one") {
		t.Fatal("legacy signer group was deletable by failover")
	}
	if authID, ok := cache.Get("compaction::legacy"); !ok || authID != "one" {
		t.Fatal("legacy signer migrated or was removed by auth invalidation")
	}
	if _, ok := cache.Get("wrong-account"); ok {
		t.Fatal("conflict changed cache")
	}
	// The recovery must not accidentally protect ordinary groups.
	cache.SetAliases("one", "ordinary", "ordinary-alias")
	cache.SetAliases("two", "ordinary-alias")
	for _, alias := range []string{"ordinary", "ordinary-alias"} {
		if authID, ok := cache.Get(alias); !ok || authID != "two" || cache.IsProtected(alias) {
			t.Fatal("ordinary unprotected group cannot rebind")
		}
	}
	for _, group := range readPersistenceTestState(t, path).Groups {
		if hasCompactionSessionAlias(group.Aliases) && !group.Protected {
			t.Fatal("recovered signer was republished unprotected")
		}
	}
}

func TestSessionCacheProtectedRegistrationConflictAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.SetAliases("one", "ordinary", "ordinary-alias")
	if errSet := cache.SetProtectedAliases("two", "compaction::known"); errSet != nil {
		t.Fatal(errSet)
	}
	before, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	entriesBefore := make(map[string]sessionEntry, len(cache.entries))
	for alias, entry := range cache.entries {
		entriesBefore[alias] = entry
	}
	if errSet := cache.SetProtectedAliases("one", "ordinary", "new", "compaction::known"); errSet == nil {
		t.Fatal("protected different-account conflict accepted")
	}
	cache.SetAliases("one", "ordinary", "new", "compaction::known")
	after, errRead := os.ReadFile(path)
	if errRead != nil || string(before) != string(after) || !reflect.DeepEqual(entriesBefore, cache.entries) {
		t.Fatal("rejected registration changed disk or memory")
	}
}

func TestSessionCacheProtectedRegistrationRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.state")
	cache := newPersistenceTestCache(t, 1)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	if errSet := cache.SetProtectedAliases("one", "compaction::oversized", "alias"); errSet == nil {
		t.Fatal("self-evicted registration returned success")
	}
	if cache.Len() != 0 || len(readPersistenceTestState(t, path).Groups) != 0 {
		t.Fatal("oversized registration exceeded capacity or was persisted")
	}
	if errSet := cache.SetProtectedAliases("one", "compaction::old"); errSet != nil {
		t.Fatal(errSet)
	}
	if errSet := cache.SetProtectedAliases("two", "compaction::new"); errSet != nil {
		t.Fatal(errSet)
	}
	if _, ok := cache.Get("compaction::old"); ok || !cache.IsProtected("compaction::new") {
		t.Fatal("protection prevented bounded eviction")
	}
	cache.mu.Lock()
	entry := cache.entries["compaction::new"]
	cache.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
	cache.mu.Unlock()
	cache.cleanup()
	if cache.Len() != 0 || len(readPersistenceTestState(t, path).Groups) != 0 {
		t.Fatal("protection prevented bounded expiration")
	}
}

func TestSessionCacheProtectedRegistrationStickyError(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(filepath.Join(blocked, "sessions.state")); errEnable != nil {
		t.Fatal(errEnable)
	}
	if errRemove := os.Remove(blocked); errRemove != nil {
		t.Fatal(errRemove)
	}
	if errWrite := os.WriteFile(blocked, []byte("blocker"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	errSet := cache.SetProtectedAliases("one", "compaction::first")
	if errSet == nil || errSet != cache.PersistenceError() {
		t.Fatal("registration did not propagate sticky save error")
	}
	if errNext := cache.SetProtectedAliases("one", "compaction::second"); errNext != errSet {
		t.Fatal("registration did not propagate prior sticky error")
	}
	if _, ok := cache.Get("compaction::second"); ok {
		t.Fatal("registration mutated cache after sticky error")
	}
	if !cache.IsProtected("compaction::first") {
		t.Fatal("failed publication installed an unprotected signer")
	}
}

func TestSessionCacheTTLReloadAndSelectorReferences(t *testing.T) {
	cache := NewSessionCache(time.Hour)
	defer cache.Stop()
	cache.retainSelector()
	cache.Set("existing", "one")
	oldExpiry := cache.entries["existing"].expiresAt
	cache.retainSelector()
	cache.releaseSelector()
	select {
	case <-cache.stopCh:
		t.Fatal("old selector stopped shared cache during reload")
	default:
	}
	cache.SetTTL(2 * time.Hour)
	beforeSet := time.Now()
	cache.Set("new", "two")
	afterSet := time.Now()
	if expiry := cache.entries["new"].expiresAt; expiry.Before(beforeSet.Add(2*time.Hour)) || expiry.After(afterSet.Add(2*time.Hour)) {
		t.Fatal("registration did not use reloaded TTL")
	}
	if !cache.entries["existing"].expiresAt.Equal(oldExpiry) {
		t.Fatal("TTL reload changed existing expiration")
	}
	beforeTouch := time.Now()
	if !cache.Touch("existing", "one") {
		t.Fatal("touch after reload failed")
	}
	afterTouch := time.Now()
	if expiry := cache.entries["existing"].expiresAt; expiry.Before(beforeTouch.Add(2*time.Hour)) || expiry.After(afterTouch.Add(2*time.Hour)) {
		t.Fatal("touch did not use reloaded TTL")
	}
	cache.SetTTL(0)
	cache.mu.RLock()
	ttl := cache.ttl
	cache.mu.RUnlock()
	if ttl != 2*time.Hour {
		t.Fatal("invalid TTL replaced current TTL")
	}
	cache.releaseSelector()
	select {
	case <-cache.stopCh:
	default:
		t.Fatal("last selector release did not stop cleanup")
	}
	cache.releaseSelector()
	cache.Stop()
}

func TestSessionCachePersistenceRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.SetAliases("account-one", "conversation", "pck:compact", "conversation-alias")
	cache.Protect("pck:compact")
	before := readPersistenceTestState(t, path)
	if len(before.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(before.Groups))
	}

	restarted := newPersistenceTestCache(t, 100)
	if errEnable := restarted.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	for _, alias := range before.Groups[0].Aliases {
		if authID, ok := restarted.Get(alias); !ok || authID != "account-one" {
			t.Fatalf("binding not restored for %q", alias)
		}
		if !restarted.IsProtected(alias) {
			t.Fatalf("protection not restored for %q", alias)
		}
		entry := restarted.entries[alias]
		if !entry.expiresAt.Equal(before.Groups[0].ExpiresAt) || !reflect.DeepEqual(entry.aliases, before.Groups[0].Aliases) {
			t.Fatal("restart changed expiry or aliases")
		}
	}
	if restarted.PersistenceError() != nil {
		t.Fatal(restarted.PersistenceError())
	}
}

func TestSessionCachePersistenceIdleTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.SetAliases("one", "conversation", "signed-digest")
	cache.Protect("signed-digest")

	// Model two idle hours by aging the last activity timestamp, without sleeps.
	cache.mu.Lock()
	entry := cache.entries["conversation"]
	idleExpiry := entry.expiresAt.Add(-2 * time.Hour)
	cache.replaceAliasGroupsLocked(entry.authID, idleExpiry, entry.aliases, entry)
	cache.persistLocked()
	cache.mu.Unlock()
	if cache.PersistenceError() != nil {
		t.Fatal(cache.PersistenceError())
	}
	if !readPersistenceTestState(t, path).Groups[0].ExpiresAt.Equal(idleExpiry) {
		t.Fatal("idle expiry was not persisted")
	}

	restarted := newPersistenceTestCache(t, 100)
	if errEnable := restarted.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	for _, alias := range []string{"conversation", "signed-digest"} {
		if authID, ok := restarted.Get(alias); !ok || authID != "one" || !restarted.IsProtected(alias) {
			t.Fatal("two-hour idle restart lost protected account binding")
		}
		if !restarted.entries[alias].expiresAt.Equal(idleExpiry) {
			t.Fatal("idle restart or non-refreshing read reset expiry")
		}
	}
	if !readPersistenceTestState(t, path).Groups[0].ExpiresAt.Equal(idleExpiry) {
		t.Fatal("non-refreshing read changed persisted expiry")
	}

	beforeTouch := time.Now()
	if !restarted.Touch("conversation", "one") {
		t.Fatal("idle conversation touch failed")
	}
	afterTouch := time.Now()
	refreshed := readPersistenceTestState(t, path).Groups[0]
	if refreshed.ExpiresAt.Before(beforeTouch.Add(restarted.ttl)) || refreshed.ExpiresAt.After(afterTouch.Add(restarted.ttl)) || !refreshed.Protected {
		t.Fatal("touch did not persist the refreshed idle expiry and protection")
	}
	finalCache := newPersistenceTestCache(t, 100)
	if errEnable := finalCache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	if !finalCache.entries["signed-digest"].expiresAt.Equal(refreshed.ExpiresAt) || !finalCache.IsProtected("conversation") {
		t.Fatal("refreshed idle expiry or protection lost on second restart")
	}
}

func TestSessionCachePersistenceExcludesStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	now := time.Now()
	liveExpiry := now.Add(2 * time.Hour)
	writePersistenceTestState(t, path,
		sessionCacheRecord{AuthID: "one", ExpiresAt: liveExpiry, Aliases: []string{"live", "alias"}},
		sessionCacheRecord{AuthID: "two", ExpiresAt: now.Add(-time.Hour), Aliases: []string{"stale", "stale-alias"}, Protected: true},
	)
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	if cache.Len() != 2 {
		t.Fatalf("loaded %d aliases, want 2", cache.Len())
	}
	if _, ok := cache.Get("stale"); ok || cache.IsProtected("stale-alias") {
		t.Fatal("stale protected binding survived")
	}
	if !cache.entries["live"].expiresAt.Equal(liveExpiry) {
		t.Fatal("load refreshed expiry")
	}
	cache.Set("another", "three")
	for _, group := range readPersistenceTestState(t, path).Groups {
		if group.AuthID == "two" {
			t.Fatal("stale group persisted")
		}
	}
}

func TestSessionCachePersistencePrivateAtomicReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	path := filepath.Join(dir, "sessions.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.Set("first", "one")
	old, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	oldInfo, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatal(errStat)
	}
	if errChmod := os.Chmod(path, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	cache.Set("second", "two")
	if cache.PersistenceError() != nil {
		t.Fatal(cache.PersistenceError())
	}
	newInfo, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatal(errStat)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("snapshot was modified in place instead of replaced")
	}
	if runtime.GOOS != "windows" {
		dirInfo, errDir := os.Stat(dir)
		if errDir != nil {
			t.Fatal(errDir)
		}
		if newInfo.Mode().Perm() != 0o600 || dirInfo.Mode().Perm() != 0o700 {
			t.Fatalf("permissions file=%o directory=%o", newInfo.Mode().Perm(), dirInfo.Mode().Perm())
		}
	}
	var oldState sessionCacheFile
	if errDecode := json.Unmarshal(old, &oldState); errDecode != nil || len(oldState.Groups) != 1 {
		t.Fatal("previous complete snapshot invalid")
	}
	if len(readPersistenceTestState(t, path).Groups) != 2 {
		t.Fatal("replacement snapshot incomplete")
	}
	files, errList := os.ReadDir(dir)
	if errList != nil || len(files) != 1 || files[0].Name() != "sessions.json" {
		t.Fatalf("temporary file left behind: %v, %v", files, errList)
	}
}

func TestSessionCachePersistenceExistingDirectoryModeUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "auths")
	if errMkdir := os.Mkdir(dir, 0o750); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	// Set an exact non-private mode regardless of the test runner's umask.
	if errChmod := os.Chmod(dir, 0o750); errChmod != nil {
		t.Fatal(errChmod)
	}
	path := filepath.Join(dir, "sessions.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.Set("first", "one")
	cache.Set("second", "two")
	if cache.PersistenceError() != nil {
		t.Fatal(cache.PersistenceError())
	}
	dirInfo, errDir := os.Stat(dir)
	if errDir != nil {
		t.Fatal(errDir)
	}
	fileInfo, errFile := os.Stat(path)
	if errFile != nil {
		t.Fatal(errFile)
	}
	if dirInfo.Mode().Perm() != 0o750 || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("existing directory changed or snapshot not private: directory=%o file=%o", dirInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}
}

func TestSessionCachePersistenceBadLoadNeverOverwritten(t *testing.T) {
	for _, bad := range []string{
		`not-json-secret-account`,
		`{"version":2,"groups":[]}`,
		`{"version":1,"groups":[{"auth_id":"secret-account","aliases":["secret-session"]}]}`,
		`{"version":1,"groups":[{"auth_id":"secret-account","expires_at":"2099-01-01T00:00:00Z","aliases":["secret-session","secret-session"]}]}`,
	} {
		t.Run(bad, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret-session.json")
			if errWrite := os.WriteFile(path, []byte(bad), 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			cache := newPersistenceTestCache(t, 100)
			errEnable := cache.EnablePersistence(path)
			if errEnable == nil || cache.PersistenceError() == nil {
				t.Fatal("bad load did not fail closed")
			}
			if strings.Contains(errEnable.Error(), "secret") || strings.Contains(errEnable.Error(), path) {
				t.Fatal("load error leaked identifiers")
			}
			if errSet := cache.SetProtectedAliases("new-account", "compaction::new"); errSet != errEnable {
				t.Fatal("registration did not propagate sticky load error")
			}
			cache.Set("new", "new-account")
			cache.Protect("new")
			cache.Invalidate("new")
			cache.cleanup()
			got, errRead := os.ReadFile(path)
			if errRead != nil || string(got) != bad {
				t.Fatal("failed load was overwritten")
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		// Reading a directory fails even when tests run with elevated privileges.
		cache := newPersistenceTestCache(t, 100)
		if errEnable := cache.EnablePersistence(t.TempDir()); errEnable == nil || cache.PersistenceError() == nil {
			t.Fatal("unreadable state did not fail closed")
		}
	})
}

func TestSessionCachePersistenceMutations(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*SessionCache)
	}{
		{"set", func(c *SessionCache) { c.Set("new", "two") }},
		{"aliases", func(c *SessionCache) { c.SetAliases("one", "a", "new-alias") }},
		{"refresh", func(c *SessionCache) { c.GetAndRefresh("b") }},
		{"touch", func(c *SessionCache) { c.Touch("b", "one") }},
		{"delete", func(c *SessionCache) { c.CompareAndDelete("a", "one") }},
		{"invalidate", func(c *SessionCache) { c.Invalidate("a") }},
		{"invalidate-auth", func(c *SessionCache) { c.InvalidateAuth("one") }},
		{"protect", func(c *SessionCache) { c.Protect("b") }},
		{"capacity", func(c *SessionCache) { c.SetAliases("two", "new-a", "new-b") }},
		{"cleanup", func(c *SessionCache) {
			c.mu.Lock()
			entry := c.entries["a"]
			c.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
			c.mu.Unlock()
			c.cleanup()
		}},
		{"expired-get", func(c *SessionCache) {
			c.mu.Lock()
			entry := c.entries["a"]
			c.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
			c.mu.Unlock()
			c.Get("a")
		}},
		{"expired-refresh", func(c *SessionCache) {
			c.mu.Lock()
			entry := c.entries["a"]
			c.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
			c.mu.Unlock()
			c.GetAndRefresh("a")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sessions.json")
			writePersistenceTestState(t, path, sessionCacheRecord{
				AuthID: "one", ExpiresAt: time.Now().Add(time.Hour), Aliases: []string{"a", "b"},
			})
			before, errRead := os.ReadFile(path)
			if errRead != nil {
				t.Fatal(errRead)
			}
			cache := newPersistenceTestCache(t, 3)
			if errEnable := cache.EnablePersistence(path); errEnable != nil {
				t.Fatal(errEnable)
			}
			tc.mutate(cache)
			if cache.PersistenceError() != nil {
				t.Fatal(cache.PersistenceError())
			}
			after, errRead := os.ReadFile(path)
			if errRead != nil || string(before) == string(after) {
				t.Fatal("mutation was not synchronously persisted")
			}
			restarted := newPersistenceTestCache(t, 3)
			if errEnable := restarted.EnablePersistence(path); errEnable != nil {
				t.Fatal(errEnable)
			}
			if len(cache.entries) != len(restarted.entries) {
				t.Fatal("persisted alias count differs")
			}
			for alias, entry := range cache.entries {
				got, ok := restarted.entries[alias]
				if !ok || !sameSessionEntryGroup(entry, got) {
					t.Fatalf("persisted group differs for %q", alias)
				}
			}
		})
	}
}

func TestSessionCachePersistenceSaveErrorRedacted(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "secret-account")
	path := filepath.Join(blocked, "secret-session.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	// Replace the pinned parent with a regular file to force a save error.
	if errRemove := os.Remove(blocked); errRemove != nil {
		t.Fatal(errRemove)
	}
	if errWrite := os.WriteFile(blocked, []byte("blocker"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cache.Set("secret-session", "secret-account")
	errSave := cache.PersistenceError()
	if errSave == nil || strings.Contains(errSave.Error(), "secret") || strings.Contains(errSave.Error(), path) {
		t.Fatalf("save error missing or not redacted: %v", errSave)
	}
	cache.InvalidateAuth("secret-account")
	if cache.PersistenceError() != errSave {
		t.Fatal("save error was not sticky")
	}
}

func TestSessionCacheProtectedInvalidationAndAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	cache := newPersistenceTestCache(t, 100)
	if errEnable := cache.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	cache.SetAliases("one", "a", "b")
	cache.Set("unprotected", "one")
	cache.Protect("a")
	expiry := cache.entries["a"].expiresAt
	cache.Protect("b")
	if !cache.entries["b"].expiresAt.Equal(expiry) {
		t.Fatal("protect refreshed TTL")
	}
	if cache.CompareAndDelete("b", "one") {
		t.Fatal("CompareAndDelete removed protected alias")
	}
	cache.InvalidateAuth("one")
	if _, ok := cache.Get("unprotected"); ok {
		t.Fatal("unprotected group survived invalidation")
	}
	cache.SetAliases("two", "a", "new-wrong-account")
	if _, ok := cache.Get("new-wrong-account"); ok {
		t.Fatal("conflicting protected re-alias partially applied")
	}
	cache.Set("b", "two")
	if authID, ok := cache.Get("a"); !ok || authID != "one" {
		t.Fatal("protected auth changed")
	}
	cache.Set("other", "one")
	cache.SetAliases("one", "other", "b", "new")
	cache.Touch("new", "one")
	cache.GetAndRefresh("other")
	for _, alias := range []string{"a", "b", "other", "new"} {
		if !cache.IsProtected(alias) {
			t.Fatalf("protection lost on merge/touch for %q", alias)
		}
	}
	// Explicit invalidation is allowed, but must preserve surviving protection.
	cache.Invalidate("a")
	if _, ok := cache.Get("a"); ok || !cache.IsProtected("b") {
		t.Fatal("explicit alias invalidation lost surviving protection")
	}
	restarted := newPersistenceTestCache(t, 100)
	if errEnable := restarted.EnablePersistence(path); errEnable != nil {
		t.Fatal(errEnable)
	}
	if !restarted.IsProtected("new") || restarted.CompareAndDelete("new", "one") {
		t.Fatal("protected invalidation semantics lost after restart")
	}
}

func TestSessionCacheProtectedCapacityAndExpiration(t *testing.T) {
	t.Run("eviction-persists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sessions.json")
		cache := newPersistenceTestCache(t, 2)
		if errEnable := cache.EnablePersistence(path); errEnable != nil {
			t.Fatal(errEnable)
		}
		cache.SetAliases("one", "conversation", "signed-digest")
		cache.Protect("signed-digest")
		cache.Set("new-conversation", "two")
		if cache.Len() != 1 {
			t.Fatal("protected groups exceeded capacity")
		}
		restarted := newPersistenceTestCache(t, 2)
		if errEnable := restarted.EnablePersistence(path); errEnable != nil {
			t.Fatal(errEnable)
		}
		for _, c := range []*SessionCache{cache, restarted} {
			for _, alias := range []string{"conversation", "signed-digest"} {
				if _, ok := c.Get(alias); ok || c.IsProtected(alias) {
					t.Fatal("evicted group must be a cold miss, not a migrated binding")
				}
			}
			if authID, ok := c.Get("new-conversation"); !ok || authID != "two" {
				t.Fatal("capacity eviction lost newest group")
			}
		}
	})
	t.Run("oversized-protected-group", func(t *testing.T) {
		cache := newPersistenceTestCache(t, 2)
		cache.Set("a", "one")
		cache.Protect("a")
		cache.SetAliases("one", "a", "b", "c")
		if cache.Len() != 0 {
			t.Fatal("oversized protected group exceeded capacity")
		}
	})
	t.Run("restore-enforces-capacity", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sessions.json")
		expiry := time.Now().Add(time.Hour)
		writePersistenceTestState(t, path,
			sessionCacheRecord{AuthID: "one", ExpiresAt: expiry, Aliases: []string{"old", "signed-digest"}, Protected: true},
			sessionCacheRecord{AuthID: "two", ExpiresAt: expiry, Aliases: []string{"new"}, Protected: true},
		)
		cache := newPersistenceTestCache(t, 2)
		if errEnable := cache.EnablePersistence(path); errEnable != nil {
			t.Fatal(errEnable)
		}
		if cache.Len() != 1 || !cache.IsProtected("new") {
			t.Fatal("restored protected groups exceeded capacity or lost protection")
		}
		if _, ok := cache.Get("signed-digest"); ok {
			t.Fatal("restore did not evict complete oldest group")
		}
	})
	t.Run("expiration-persists", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sessions.json")
		cache := newPersistenceTestCache(t, 2)
		if errEnable := cache.EnablePersistence(path); errEnable != nil {
			t.Fatal(errEnable)
		}
		cache.SetAliases("one", "a", "signed-digest")
		cache.Protect("a")
		cache.mu.Lock()
		entry := cache.entries["a"]
		cache.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
		cache.mu.Unlock()
		cache.cleanup()
		if cache.Len() != 0 || cache.IsProtected("a") || len(readPersistenceTestState(t, path).Groups) != 0 {
			t.Fatal("protection prevented TTL expiration")
		}
		if _, ok := cache.Get("signed-digest"); ok {
			t.Fatal("expired compaction key must be a cold miss requiring recompaction")
		}
	})
}
