package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type sessionCacheFile struct {
	Version int                  `json:"version"`
	Groups  []sessionCacheRecord `json:"groups"`
}

type sessionCacheRecord struct {
	AuthID    string    `json:"auth_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Aliases   []string  `json:"aliases"`
	Protected bool      `json:"protected,omitempty"`
}

// EnablePersistence loads live alias groups before the cache is used. Newly
// created directories are private; existing directory modes are unchanged.
// One cache owns each file; concurrent processes sharing it are not supported.
// Errors are sticky so a selector can fail closed, including after a failed
// initialization.
func (c *SessionCache) EnablePersistence(path string) error {
	if c == nil {
		return errors.New("session cache persistence: nil cache")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistenceErr != nil {
		return c.persistenceErr
	}
	if strings.TrimSpace(path) == "" || c.persistencePath != "" || len(c.entries) != 0 {
		c.persistenceErr = errors.New("session cache persistence: requires a path and an unused cache")
		return c.persistenceErr
	}

	// Do not expose filesystem paths, aliases, auth IDs, or parser input in errors.
	data, errRead := os.ReadFile(path)
	if errRead != nil && !errors.Is(errRead, os.ErrNotExist) {
		c.persistenceErr = errors.New("session cache persistence: read failed")
		return c.persistenceErr
	}
	var state sessionCacheFile
	if errRead == nil {
		if errDecode := json.Unmarshal(data, &state); errDecode != nil || state.Version != 1 {
			c.persistenceErr = errors.New("session cache persistence: invalid state")
			return c.persistenceErr
		}
		// Validate the whole file before modifying the cache, including stale groups.
		seen := make(map[string]bool)
		for _, record := range state.Groups {
			if record.AuthID == "" || record.ExpiresAt.IsZero() || len(record.Aliases) == 0 {
				c.persistenceErr = errors.New("session cache persistence: invalid group")
				return c.persistenceErr
			}
			for _, alias := range record.Aliases {
				if alias == "" || seen[alias] {
					c.persistenceErr = errors.New("session cache persistence: invalid aliases")
					return c.persistenceErr
				}
				seen[alias] = true
			}
		}
	}

	c.ensureInitializedLocked()
	now := time.Now()
	// Restore complete groups before enforcing capacity, including protection.
	// Evicted signed-compaction aliases require recompaction in the selector.
	for _, record := range state.Groups {
		if !now.Before(record.ExpiresAt) {
			continue
		}
		entry := sessionEntry{
			authID: record.AuthID, expiresAt: record.ExpiresAt,
			aliases: append([]string(nil), record.Aliases...),
			// Older snapshots could publish a signer before its Protect call.
			protected: record.Protected || hasCompactionSessionAlias(record.Aliases),
		}
		primary := entry.aliases[0]
		c.groups[primary] = entry
		for _, alias := range entry.aliases {
			c.entries[alias] = entry
		}
		c.evictionElements[primary] = c.evictionOrder.PushBack(primary)
	}
	if c.maxEntries > 0 {
		c.evictExcessLocked()
	}
	c.persistenceDirty = false
	c.persistencePath = path
	return nil
}

// PersistenceError returns the first load or save error. A non-nil error means
// the persisted bindings cannot be trusted; callers must fail closed.
func (c *SessionCache) PersistenceError() error {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.persistenceErr
}

// persistLocked writes only complete mutations while the cache lock is held.
// A load failure never enables writing, so a bad file cannot be overwritten.
func (c *SessionCache) persistLocked() {
	if c.persistencePath == "" || !c.persistenceDirty || c.persistenceErr != nil {
		return
	}
	state := sessionCacheFile{Version: 1, Groups: make([]sessionCacheRecord, 0, len(c.groups))}
	now := time.Now()
	for _, group := range c.groups {
		if now.Before(group.expiresAt) {
			state.Groups = append(state.Groups, sessionCacheRecord{
				AuthID: group.authID, ExpiresAt: group.expiresAt,
				Aliases: group.aliases, Protected: group.protected,
			})
		}
	}
	sort.Slice(state.Groups, func(i, j int) bool {
		return state.Groups[i].Aliases[0] < state.Groups[j].Aliases[0]
	})
	if errSave := writeSessionCacheFile(c.persistencePath, state); errSave != nil {
		c.persistenceErr = errSave
		return
	}
	c.persistenceDirty = false
}

func writeSessionCacheFile(path string, state sessionCacheFile) error {
	data, errMarshal := json.Marshal(state)
	if errMarshal != nil {
		return errors.New("session cache persistence: encode failed")
	}
	dir := filepath.Dir(path)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return errors.New("session cache persistence: create directory failed")
	}
	file, errCreate := os.CreateTemp(dir, ".session-cache-*.tmp")
	if errCreate != nil {
		return errors.New("session cache persistence: create temporary file failed")
	}
	tmp := file.Name()
	defer func() { _ = os.Remove(tmp) }()
	// CreateTemp creates mode 0600 files, independent of the old target's mode.
	_, errWrite := file.Write(data)
	if errWrite == nil {
		errWrite = file.Sync()
	}
	errClose := file.Close()
	if errWrite != nil || errClose != nil {
		return errors.New("session cache persistence: write temporary file failed")
	}
	if errRename := os.Rename(tmp, path); errRename != nil {
		return errors.New("session cache persistence: replace file failed")
	}
	return nil
}
