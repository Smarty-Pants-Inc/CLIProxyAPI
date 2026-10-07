package auth

import (
	"container/list"
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	maxStableSessionAliases  = 64
	defaultMaxSessionEntries = 65536
)

// sessionEntry stores an auth binding, its identifier aliases, and expiration.
type sessionEntry struct {
	authID    string
	expiresAt time.Time
	aliases   []string
	protected bool
}

// SessionCache provides TTL-based session to auth mapping with automatic cleanup.
type SessionCache struct {
	mu               sync.RWMutex
	entries          map[string]sessionEntry
	groups           map[string]sessionEntry
	evictionOrder    *list.List
	evictionElements map[string]*list.Element
	maxEntries       int
	ttl              time.Duration
	stopCh           chan struct{}
	stopOnce         sync.Once
	selectorRefs     int
	persistencePath  string
	persistenceDir   string // resolved directory identity at enable time
	persistenceErr   error
	persistenceDirty bool
}

// NewSessionCache creates a cache with the specified TTL.
// A background goroutine periodically cleans expired entries.
func NewSessionCache(ttl time.Duration) *SessionCache {
	return NewSessionCacheWithCapacity(ttl, defaultMaxSessionEntries)
}

// NewSessionCacheWithCapacity creates a cache with the specified TTL and max entries limit.
func NewSessionCacheWithCapacity(ttl time.Duration, maxEntries int) *SessionCache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = defaultMaxSessionEntries
	}
	c := &SessionCache{
		entries:          make(map[string]sessionEntry),
		groups:           make(map[string]sessionEntry),
		evictionOrder:    list.New(),
		evictionElements: make(map[string]*list.Element),
		maxEntries:       maxEntries,
		ttl:              ttl,
		stopCh:           make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

func (c *SessionCache) ensureInitializedLocked() {
	if c.entries == nil {
		c.entries = make(map[string]sessionEntry)
	}
	if c.groups == nil {
		c.groups = make(map[string]sessionEntry)
	}
	if c.evictionOrder == nil {
		c.evictionOrder = list.New()
	}
	if c.evictionElements == nil {
		c.evictionElements = make(map[string]*list.Element)
	}
}

// Get retrieves the auth ID bound to a session, if still valid.
// Does NOT refresh the TTL on access.
func (c *SessionCache) Get(sessionID string) (string, bool) {
	if c == nil || sessionID == "" {
		return "", false
	}
	c.mu.RLock()
	now := time.Now()
	entry, ok := c.entries[sessionID]
	if ok && now.Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.authID, true
	}
	c.mu.RUnlock()
	if !ok {
		return "", false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	entry, ok = c.entries[sessionID]
	if !ok {
		return "", false
	}
	if time.Now().Before(entry.expiresAt) {
		return entry.authID, true
	}
	c.removeAliasGroupLocked(entry)
	c.persistLocked()
	return "", false
}

// GetAndRefresh retrieves the auth ID bound to a session and refreshes the TTL
// for every identifier known to represent the same logical session.
func (c *SessionCache) GetAndRefresh(sessionID string) (string, bool) {
	if c == nil || sessionID == "" {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	entry, ok := c.entries[sessionID]
	if !ok {
		return "", false
	}
	now := time.Now()
	if !now.Before(entry.expiresAt) {
		c.removeAliasGroupLocked(entry)
		c.persistLocked()
		return "", false
	}

	aliases := compactSessionAliases(mergeSessionAliases([]string{sessionID}, entry.aliases...))
	c.replaceAliasGroupsLocked(entry.authID, now.Add(c.ttl), aliases, entry)
	c.persistLocked()
	return entry.authID, true
}

// Set binds a session to an auth ID with TTL refresh. Existing aliases for the
// same logical session remain attached when the binding is refreshed or moved.
func (c *SessionCache) Set(sessionID, authID string) {
	if c == nil {
		return
	}
	c.SetAliases(authID, sessionID)
}

// SetAliases binds multiple identifiers for one logical session to an auth ID.
func (c *SessionCache) SetAliases(authID string, sessionIDs ...string) {
	_ = c.setAliases(authID, false, sessionIDs...)
}

// SetProtectedAliases atomically registers and protects one alias group, then
// publishes one complete snapshot. Callers register each compaction digest as
// its own group, separately from mutable routing aliases.
func (c *SessionCache) SetProtectedAliases(authID string, sessionIDs ...string) error {
	return c.setAliases(authID, true, sessionIDs...)
}

// SetProtectedBindings registers independent bindings in one synchronous snapshot.
// Existing alias groups stay separate; unlike SetProtectedAliases, the supplied
// identifiers do not become aliases of one another.
func (c *SessionCache) SetProtectedBindings(ctx context.Context, authID string, sessionIDs ...string) error {
	return c.mutateProtectedBindings(ctx, authID, false, sessionIDs...)
}

// touchProtectedBindings refreshes only live, protected evidence for this signer.
func (c *SessionCache) touchProtectedBindings(ctx context.Context, authID string, sessionIDs ...string) error {
	return c.mutateProtectedBindings(ctx, authID, true, sessionIDs...)
}

func (c *SessionCache) mutateProtectedBindings(ctx context.Context, authID string, requireExisting bool, sessionIDs ...string) error {
	if c == nil || authID == "" {
		return errors.New("session cache: requires cache and auth ID")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.persistenceErr != nil {
		return c.persistenceErr
	}
	c.ensureInitializedLocked()
	requested := mergeSessionAliases(nil, sessionIDs...)
	if len(requested) == 0 {
		return nil
	}
	now := time.Now()
	previous := make(map[string]sessionEntry, len(requested))
	planned := make(map[string]bool, len(requested))
	groups := make([]sessionEntry, 0, len(requested))
	retainedAliases := 0
	// Preflight every conflict and the capacity of the complete batch before
	// changing any group. Do not acknowledge a partially retained output event.
	for _, key := range requested {
		entry, exists := c.entries[key]
		live := exists && now.Before(entry.expiresAt)
		if requireExisting && (!live || entry.authID != authID || !entry.protected) {
			return errors.New("session cache: signer binding unavailable")
		}
		if live && (entry.protected || hasCompactionSessionAlias(entry.aliases)) && entry.authID != authID {
			return errors.New("session cache: protected alias account conflict")
		}
		aliases := []string{key}
		if exists {
			previous[entry.aliases[0]] = entry
			if live {
				aliases = entry.aliases
			}
		}
		primary := aliases[0]
		if planned[primary] {
			continue
		}
		planned[primary] = true
		retainedAliases += len(aliases)
		groups = append(groups, sessionEntry{
			authID: authID, expiresAt: now.Add(c.ttl),
			aliases: append([]string(nil), aliases...), protected: true,
		})
	}
	if c.maxEntries > 0 && retainedAliases > c.maxEntries {
		return errors.New("session cache: registration not retained")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Remove all target groups first, then install them newest. Capacity may
	// evict other groups, but cannot evict any part of this admitted batch.
	for _, entry := range previous {
		c.removeAliasGroupLocked(entry)
	}
	for _, group := range groups {
		c.replaceAliasGroupsLocked(authID, group.expiresAt, group.aliases, group)
	}
	c.persistLocked()
	if c.persistenceErr != nil {
		return c.persistenceErr
	}
	now = time.Now()
	for _, key := range requested {
		entry, retained := c.entries[key]
		if !retained || entry.authID != authID || !entry.protected || !now.Before(entry.expiresAt) {
			return errors.New("session cache: registration not retained")
		}
	}
	return nil
}

func (c *SessionCache) setAliases(authID string, protect bool, sessionIDs ...string) error {
	if c == nil || authID == "" {
		return errors.New("session cache: requires cache and auth ID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.persistenceErr != nil {
		return c.persistenceErr
	}
	c.ensureInitializedLocked()
	now := time.Now()
	requested := mergeSessionAliases(nil, sessionIDs...)
	if len(requested) == 0 {
		return errors.New("session cache: requires aliases")
	}

	// Check every live group before changing memory or publishing a snapshot.
	for _, sessionID := range requested {
		if entry, ok := c.entries[sessionID]; ok && now.Before(entry.expiresAt) &&
			(entry.protected || hasCompactionSessionAlias(entry.aliases)) && entry.authID != authID {
			return errors.New("session cache: protected alias account conflict")
		}
	}
	aliases := requested
	previousGroups := make([]sessionEntry, 0, len(requested))
	for _, sessionID := range requested {
		entry, ok := c.entries[sessionID]
		if !ok {
			continue
		}
		if !now.Before(entry.expiresAt) {
			c.removeAliasGroupLocked(entry)
			continue
		}
		previousGroups = append(previousGroups, entry)
		aliases = mergeSessionAliases(aliases, entry.aliases...)
	}
	aliases = compactSessionAliases(aliases)
	if protect {
		// Protection is supplied to replacement before any entry is installed.
		previousGroups = append(previousGroups, sessionEntry{authID: authID, protected: true})
	}
	c.replaceAliasGroupsLocked(authID, now.Add(c.ttl), aliases, previousGroups...)
	c.persistLocked()
	if c.persistenceErr != nil {
		return c.persistenceErr
	}
	for _, alias := range requested {
		entry, ok := c.entries[alias]
		if !ok || entry.authID != authID || !time.Now().Before(entry.expiresAt) || (protect && !entry.protected) {
			return errors.New("session cache: registration not retained")
		}
	}
	return nil
}

func hasCompactionSessionAlias(aliases []string) bool {
	for _, alias := range aliases {
		if strings.HasPrefix(alias, "compaction::") {
			return true
		}
	}
	return false
}

func (c *SessionCache) replaceAliasGroupsLocked(authID string, expiresAt time.Time, aliases []string, previousGroups ...sessionEntry) {
	protected := hasCompactionSessionAlias(aliases)
	for _, previous := range previousGroups {
		if (previous.protected || hasCompactionSessionAlias(previous.aliases)) && previous.authID != authID {
			return
		}
		protected = protected || previous.protected || hasCompactionSessionAlias(previous.aliases)
	}
	for _, previous := range previousGroups {
		c.removeAliasGroupLocked(previous)
	}
	if len(aliases) == 0 {
		return
	}
	primaryKey := aliases[0]
	if existing, ok := c.groups[primaryKey]; ok {
		c.removeAliasGroupLocked(existing)
	}
	entry := sessionEntry{authID: authID, expiresAt: expiresAt, aliases: append([]string(nil), aliases...), protected: protected}
	c.persistenceDirty = true
	c.groups[primaryKey] = entry
	for _, alias := range aliases {
		c.entries[alias] = entry
	}
	c.evictionElements[primaryKey] = c.evictionOrder.PushBack(primaryKey)
	if c.maxEntries > 0 && len(c.entries) > c.maxEntries {
		c.evictExcessLocked()
	}
}

func (c *SessionCache) evictExcessLocked() {
	for elem := c.evictionOrder.Front(); elem != nil && len(c.entries) > c.maxEntries; {
		next := elem.Next()
		primaryKey, _ := elem.Value.(string)
		group, ok := c.groups[primaryKey]
		if !ok {
			c.evictionOrder.Remove(elem)
			delete(c.evictionElements, primaryKey)
		} else {
			c.removeAliasGroupLocked(group)
		}
		elem = next
	}
	// Protection prevents account migration, not capacity eviction. A signed
	// compaction alias cold miss must require recompaction in the selector.
}

func (c *SessionCache) removeAliasGroupLocked(entry sessionEntry) {
	if len(entry.aliases) == 0 {
		return
	}
	primaryKey := entry.aliases[0]
	if currentGroup, ok := c.groups[primaryKey]; ok && sameSessionEntryGroup(currentGroup, entry) {
		c.persistenceDirty = true
		delete(c.groups, primaryKey)
		if elem, ok := c.evictionElements[primaryKey]; ok {
			c.evictionOrder.Remove(elem)
			delete(c.evictionElements, primaryKey)
		}
	}
	for _, alias := range entry.aliases {
		current, ok := c.entries[alias]
		if !ok || !sameSessionEntryGroup(current, entry) {
			continue
		}
		c.persistenceDirty = true
		delete(c.entries, alias)
	}
}

func sameSessionEntryGroup(left, right sessionEntry) bool {
	return left.authID == right.authID && left.protected == right.protected && left.expiresAt.Equal(right.expiresAt) &&
		equalSessionAliases(left.aliases, right.aliases)
}

func compactSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, isLocalPromptCacheSessionAlias)
}

func compactHomeSessionAliases(aliases []string) []string {
	return compactSessionAliasesWith(aliases, func(alias string) bool {
		return strings.HasPrefix(alias, "pck:")
	})
}

func compactSessionAliasesWith(aliases []string, isPromptCacheAlias func(string) bool) []string {
	compacted := make([]string, 0, len(aliases))
	hasPromptCacheKey := false
	stableAliases := 0
	for _, alias := range aliases {
		if isPromptCacheAlias(alias) {
			if hasPromptCacheKey {
				continue
			}
			hasPromptCacheKey = true
		} else {
			if stableAliases >= maxStableSessionAliases {
				continue
			}
			stableAliases++
		}
		compacted = append(compacted, alias)
	}
	return compacted
}

func isLocalPromptCacheSessionAlias(alias string) bool {
	if strings.HasPrefix(alias, "pck:") {
		return true
	}
	_, sessionAndModel, ok := strings.Cut(alias, "::")
	return ok && strings.HasPrefix(sessionAndModel, "pck:")
}

func equalSessionAliases(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mergeSessionAliases(existing []string, candidates ...string) []string {
	aliases := make([]string, 0, len(existing)+len(candidates))
	seen := make(map[string]struct{}, cap(aliases))
	add := func(alias string) {
		if alias == "" {
			return
		}
		if _, ok := seen[alias]; ok {
			return
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	for _, alias := range existing {
		add(alias)
	}
	for _, alias := range candidates {
		add(alias)
	}
	return aliases
}

// Touch refreshes the expiration for a session binding if it currently matches expectedAuthID.
func (c *SessionCache) Touch(sessionID, expectedAuthID string) bool {
	if c == nil || sessionID == "" || expectedAuthID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	now := time.Now()
	entry, ok := c.entries[sessionID]
	if !ok || entry.authID != expectedAuthID || !now.Before(entry.expiresAt) {
		return false
	}
	aliases := compactSessionAliases(mergeSessionAliases([]string{sessionID}, entry.aliases...))
	c.replaceAliasGroupsLocked(expectedAuthID, now.Add(c.ttl), aliases, entry)
	c.persistLocked()
	return true
}

// CompareAndDelete removes an unprotected session binding only if it is
// currently bound to expectedAuthID.
func (c *SessionCache) CompareAndDelete(sessionID, expectedAuthID string) bool {
	if c == nil || sessionID == "" || expectedAuthID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	entry, ok := c.entries[sessionID]
	if !ok || entry.authID != expectedAuthID || entry.protected {
		return false
	}
	c.removeAliasGroupLocked(entry)

	surviving := make([]string, 0, len(entry.aliases))
	for _, alias := range entry.aliases {
		if alias != sessionID {
			surviving = append(surviving, alias)
		}
	}
	if len(surviving) > 0 {
		c.replaceAliasGroupsLocked(entry.authID, entry.expiresAt, surviving, entry)
	}
	c.persistLocked()
	return true
}

// Invalidate removes a specific session binding without allowing another alias
// in the same group to recreate it on its next refresh.
func (c *SessionCache) Invalidate(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	entry, ok := c.entries[sessionID]
	if !ok {
		return
	}
	c.removeAliasGroupLocked(entry)

	surviving := make([]string, 0, len(entry.aliases))
	for _, alias := range entry.aliases {
		if alias != sessionID {
			surviving = append(surviving, alias)
		}
	}
	if len(surviving) > 0 {
		c.replaceAliasGroupsLocked(entry.authID, entry.expiresAt, surviving, entry)
	}
	c.persistLocked()
}

// InvalidateAuth removes unprotected sessions bound to a specific auth ID.
// Protected groups keep their binding when an auth becomes unavailable.
func (c *SessionCache) InvalidateAuth(authID string) {
	if c == nil || authID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	for _, group := range c.groups {
		if group.authID == authID && !group.protected {
			c.removeAliasGroupLocked(group)
		}
	}
	c.persistLocked()
}

// Protect pins a live alias group to its current auth ID without refreshing TTL.
// Expiration, capacity eviction, and explicit Invalidate calls remain allowed.
func (c *SessionCache) Protect(sessionID string) {
	if c == nil || sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	entry, ok := c.entries[sessionID]
	if !ok || entry.protected {
		return
	}
	if !time.Now().Before(entry.expiresAt) {
		c.removeAliasGroupLocked(entry)
	} else {
		entry.protected = true
		c.groups[entry.aliases[0]] = entry
		for _, alias := range entry.aliases {
			c.entries[alias] = entry
		}
		c.persistenceDirty = true
	}
	c.persistLocked()
}

// IsProtected reports whether a session belongs to a live protected group.
func (c *SessionCache) IsProtected(sessionID string) bool {
	if c == nil || sessionID == "" {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[sessionID]
	return ok && entry.protected && time.Now().Before(entry.expiresAt)
}

// SetTTL changes the TTL used by future registrations and touches. Existing
// expiration timestamps, including restored snapshots, are not changed.
func (c *SessionCache) SetTTL(ttl time.Duration) {
	if c == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// retainSelector shares this cache across selector reloads. Overlapping
// selectors retain before releasing the old reference. A service may also
// borrow a stopped cache after disabling affinity or switching paths: retain
// does not restart cleanup, but lookups still enforce expiry and registrations
// enforce capacity. The service keeps the same owner for each persistence path.
func (c *SessionCache) retainSelector() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.selectorRefs++
}

// releaseSelector stops cleanup only after the last selector releases the cache.
// Each selector must release once (guarded by its own sync.Once).
func (c *SessionCache) releaseSelector() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.selectorRefs == 0 {
		return
	}
	c.selectorRefs--
	if c.selectorRefs == 0 {
		c.Stop()
	}
}

// Stop permanently terminates background cleanup, not cache operations.
// Reused caches continue to enforce expiry lazily and capacity on registration.
func (c *SessionCache) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
	})
}

func (c *SessionCache) cleanupLoop() {
	c.mu.RLock()
	interval := c.ttl / 2
	c.mu.RUnlock()
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.cleanup()
		}
	}
}

// Len returns the current count of tracked session aliases.
func (c *SessionCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *SessionCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureInitializedLocked()
	for _, group := range c.groups {
		if !now.Before(group.expiresAt) {
			c.removeAliasGroupLocked(group)
		}
	}
	c.persistLocked()
}
