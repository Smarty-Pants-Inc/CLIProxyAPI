package session

import (
	"bytes"
	"hash/maphash"
	"sync"
	"unsafe"

	"github.com/tidwall/gjson"
)

// sessionPayloadKeys lists the first path segment of every payload path read by
// extractSessionInfo, isBodyForkCandidate, ClaudeMetadataIdentities and
// hasExplicitPayloadSession. Any new payload path read by those functions must
// have its first segment listed here (TestSessionPayloadKeysCoverAllReadPaths
// enforces this).
var sessionPayloadKeys = map[string]struct{}{
	"parent_session_id": {}, "parentSessionId": {}, "parentSessionID": {},
	"parent_thread_id": {}, "parentThreadId": {}, "parentThreadID": {},
	"forked_from_thread_id": {}, "forked_from_id": {},
	"parent_conversation_id": {}, "parentConversationId": {}, "parentConversationID": {},
	"parent_id": {}, "parentId": {}, "parentID": {},
	"parent_task_id": {}, "parentTaskId": {}, "parentTaskID": {},
	"parent_action_id": {}, "parentActionId": {}, "parentActionID": {},
	"parent_session": {}, "parentSession": {},
	"parent_subagent_id": {}, "parentSubagentId": {},
	"forkSource": {}, "fork_source": {},
	"previousSessionId": {}, "previous_session_id": {},
	"metadata": {}, "extra_body": {},
	"thread_id": {}, "threadId": {},
	"cachedContent": {}, "cached_content": {},
	"session_id": {}, "sessionId": {}, "sessionID": {},
	"child_session_id": {}, "childSessionId": {},
	"task_id": {}, "taskId": {}, "taskID": {},
	"action_id": {}, "actionId": {}, "actionID": {},
	"conversation":     {},
	"prompt_cache_key": {}, "promptCacheKey": {},
	"conversation_id": {}, "conversationId": {},
	"chat_id": {}, "chatId": {},
}

const (
	// sessionPayloadRequestKey is the Gemini CLI / Antigravity envelope. Its value
	// is projected with the same key set because readers apply the same paths to it.
	sessionPayloadRequestKey = "request"
	// sessionPayloadContentsKey only matters for existence (it disables the nested
	// "request" lookup), so its potentially huge value is replaced with null.
	sessionPayloadContentsKey = "contents"

	// Payloads below this size are projected directly; hashing and caching them
	// would cost about as much as the projection itself.
	sessionProjectionCacheMinPayload = 16 << 10
	sessionProjectionCacheEntries    = 256
	// Projections above this size are not cached to keep the cache memory bounded.
	sessionProjectionCacheMaxProjection = 64 << 10
	// Payloads above this size are projected on every call and never cached.
	sessionProjectionCacheMaxPayload = 16 << 20
	// Total bytes (payload copies plus projections) held by the cache; the
	// oldest entries are evicted to stay within it.
	sessionProjectionCacheMaxBytes = 64 << 20
)

// sessionPayloadView returns the bytes session extraction should read for payload.
//
// For a valid JSON object it returns a compact object holding only the top-level
// members whose keys appear in sessionPayloadKeys (in their original order,
// duplicates included), with "contents" replaced by null and the "request"
// envelope projected the same way. Every gjson path read by session extraction
// therefore resolves to exactly the same value on the view as on the full payload,
// but no lookup has to skip over "messages", "input", "contents", "tools" or
// "system". Payloads that are empty, invalid JSON or not an object are returned
// unchanged, so lenient gjson behaviour on malformed input is preserved.
//
// Memoization rule: the view is a pure function of the payload bytes. Entries are
// looked up by payload length plus a per-process seeded 64-bit hash, but the hash
// is never trusted as identity: each entry keeps a private copy of the payload and
// is reused only when that copy is byte-for-byte equal to payload. Repeat calls
// for the same request (the handler, session.Enrich and the auth selector all
// pass the same body) reuse one projection; any different payload (a translated
// or interceptor-rewritten body, a hash collision, or nil) is projected afresh
// and replaces the entry. Payloads above sessionProjectionCacheMaxPayload are
// never cached, and the cache is bounded by entry count and total bytes. Headers
// and metadata are never cached and are always evaluated by the caller on every
// call.
func sessionPayloadView(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}
	if len(payload) < sessionProjectionCacheMinPayload {
		if view, ok := projectSessionPayload(payload); ok {
			return view
		}
		return payload
	}
	return sessionProjections.view(payload)
}

// projectSessionPayload builds the projected view described in sessionPayloadView.
// It reports false when payload is not a valid JSON object.
func projectSessionPayload(payload []byte) ([]byte, bool) {
	if !gjson.ValidBytes(payload) {
		return nil, false
	}
	root := gjson.Parse(unsafe.String(unsafe.SliceData(payload), len(payload)))
	if !root.IsObject() {
		return nil, false
	}
	return appendSessionProjection(make([]byte, 0, 256), root, true), true
}

func appendSessionProjection(dst []byte, obj gjson.Result, top bool) []byte {
	dst = append(dst, '{')
	first := true
	obj.ForEach(func(key, value gjson.Result) bool {
		var raw string
		nested := false
		_, wanted := sessionPayloadKeys[key.Str]
		switch {
		case wanted:
			raw = value.Raw
		case top && key.Str == sessionPayloadContentsKey:
			raw = "null"
		case top && key.Str == sessionPayloadRequestKey:
			raw = value.Raw
			nested = value.IsObject()
		default:
			return true
		}
		if !first {
			dst = append(dst, ',')
		}
		first = false
		dst = append(dst, key.Raw...)
		dst = append(dst, ':')
		if nested {
			dst = appendSessionProjection(dst, value, false)
		} else {
			dst = append(dst, raw...)
		}
		return true
	})
	return append(dst, '}')
}

type sessionProjectionKey struct {
	n   int
	sum uint64
}

// sessionProjectionEntry pairs a private copy of the payload bytes with their
// projection. The key hash is only a lookup hint; body is compared byte for byte
// before view is reused.
type sessionProjectionEntry struct {
	body     []byte
	view     []byte
	fallback bool
}

func (e sessionProjectionEntry) size() int {
	return len(e.body) + len(e.view)
}

type sessionProjectionCache struct {
	seed maphash.Seed
	// hash overrides the seeded maphash; tests use it to force collisions.
	hash     func([]byte) uint64
	maxBytes int

	mu      sync.Mutex
	entries map[sessionProjectionKey]sessionProjectionEntry
	ring    [sessionProjectionCacheEntries]sessionProjectionKey
	head    int
	count   int
	bytes   int
}

func newSessionProjectionCache() *sessionProjectionCache {
	return &sessionProjectionCache{
		seed:     maphash.MakeSeed(),
		maxBytes: sessionProjectionCacheMaxBytes,
		entries:  make(map[sessionProjectionKey]sessionProjectionEntry, sessionProjectionCacheEntries),
	}
}

var sessionProjections = newSessionProjectionCache()

// view returns the cached projection for payload, computing and caching it when
// absent or when the cached body under the same key differs from payload.
func (c *sessionProjectionCache) view(payload []byte) []byte {
	if len(payload) > sessionProjectionCacheMaxPayload {
		if view, ok := projectSessionPayload(payload); ok {
			return view
		}
		return payload
	}
	key := sessionProjectionKey{n: len(payload), sum: c.sum(payload)}
	if entry, ok := c.get(key); ok && bytes.Equal(entry.body, payload) {
		if entry.fallback {
			return payload
		}
		return entry.view
	}
	view, ok := projectSessionPayload(payload)
	if !ok {
		c.put(key, sessionProjectionEntry{body: bytes.Clone(payload), fallback: true})
		return payload
	}
	if len(view) <= sessionProjectionCacheMaxProjection {
		c.put(key, sessionProjectionEntry{body: bytes.Clone(payload), view: view})
	}
	return view
}

func (c *sessionProjectionCache) sum(payload []byte) uint64 {
	if c.hash != nil {
		return c.hash(payload)
	}
	return maphash.Bytes(c.seed, payload)
}

func (c *sessionProjectionCache) get(key sessionProjectionKey) (sessionProjectionEntry, bool) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	return entry, ok
}

// put stores entry under key, replacing any existing entry for the key, and
// evicts the oldest entries until both the entry cap and the byte budget hold.
func (c *sessionProjectionCache) put(key sessionProjectionKey, entry sessionProjectionEntry) {
	size := entry.size()
	if size > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, exists := c.entries[key]; exists {
		c.bytes -= old.size()
		delete(c.entries, key)
		c.removeFromRing(key)
	}
	for c.count > 0 && (c.count >= sessionProjectionCacheEntries || c.bytes+size > c.maxBytes) {
		oldest := c.ring[c.head]
		c.bytes -= c.entries[oldest].size()
		delete(c.entries, oldest)
		c.head = (c.head + 1) % sessionProjectionCacheEntries
		c.count--
	}
	c.ring[(c.head+c.count)%sessionProjectionCacheEntries] = key
	c.count++
	c.bytes += size
	c.entries[key] = entry
}

// removeFromRing drops key from the eviction ring, keeping the remaining order.
func (c *sessionProjectionCache) removeFromRing(key sessionProjectionKey) {
	for i := 0; i < c.count; i++ {
		if c.ring[(c.head+i)%sessionProjectionCacheEntries] != key {
			continue
		}
		for j := i; j < c.count-1; j++ {
			c.ring[(c.head+j)%sessionProjectionCacheEntries] = c.ring[(c.head+j+1)%sessionProjectionCacheEntries]
		}
		c.count--
		return
	}
}
