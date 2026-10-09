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
	// A projection is never built beyond this size. The builder checks the running
	// size before copying each member and aborts without copying the member that
	// would exceed it; such payloads are read directly (the legacy path).
	sessionProjectionCacheMaxProjection = 64 << 10
	// sessionPayloadMaxKeyRaw bounds the raw (quoted, escaped) length of a key that
	// can still unescape to a projected key: the longest projected key is 22 bytes,
	// each byte at most 6 escaped bytes, plus the quotes. Longer escaped keys are
	// skipped without unescaping them.
	sessionPayloadMaxKeyRaw = 22*6 + 2
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
// is never trusted as identity for a projection: each projection entry keeps a
// private copy of the payload and is reused only when that copy is byte-for-byte equal to payload. Repeat calls
// for the same request (the handler, session.Enrich and the auth selector all
// pass the same body) reuse one projection; any different payload (a translated
// or interceptor-rewritten body, a hash collision, or nil) is projected afresh
// and replaces the entry. Payloads above sessionProjectionCacheMaxPayload are
// never cached, and the cache is bounded by entry count and total bytes. Headers
// and metadata are never cached and are always evaluated by the caller on every
// call.
//
// When no projection can be used (invalid JSON, not an object, or a projection
// that would exceed sessionProjectionCacheMaxProjection) the payload itself is
// returned and read directly, exactly as before the projection existed. That
// outcome is cached as a fallback marker holding neither a projection nor a body
// copy: a fallback hit only makes the caller read its own payload, which is
// correct for any payload, so it needs no byte verification.
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
	doc := unsafe.String(unsafe.SliceData(payload), len(payload))
	i := skipJSONSpace(doc, 0)
	if i >= len(doc) || doc[i] != '{' {
		return nil, false
	}
	b := sessionProjectionBuilder{dst: make([]byte, 0, 256), limit: sessionProjectionCacheMaxProjection}
	if !b.appendObject(doc[i:], true) {
		return nil, false
	}
	return b.dst, true
}

// sessionProjectionBuilder appends the projection to dst and refuses any append
// that would grow dst beyond limit, so an oversized member is never copied.
type sessionProjectionBuilder struct {
	dst   []byte
	limit int
}

func (b *sessionProjectionBuilder) add(parts ...string) bool {
	n := len(b.dst)
	for _, p := range parts {
		n += len(p)
	}
	if n > b.limit {
		return false
	}
	for _, p := range parts {
		b.dst = append(b.dst, p...)
	}
	return true
}

// appendObject projects obj, the raw text of a JSON object taken from a payload
// that already passed gjson.ValidBytes. Members are scanned in place: keys and
// values are sliced from obj, never unescaped or copied, except that a short
// escaped key is unescaped to compare it with the projected key set. It reports
// false when the projection would exceed b.limit.
func (b *sessionProjectionBuilder) appendObject(obj string, top bool) bool {
	if !b.add("{") {
		return false
	}
	first := true
	i := 1
	for {
		i = skipJSONSpace(obj, i)
		if i >= len(obj) || obj[i] == '}' {
			break
		}
		if obj[i] == ',' {
			i++
			continue
		}
		keyEnd, keyEscaped := scanJSONString(obj, i)
		keyRaw := obj[i:keyEnd]
		i = skipJSONSpace(obj, keyEnd)
		if i < len(obj) && obj[i] == ':' {
			i++
		}
		i = skipJSONSpace(obj, i)
		valueEnd := scanJSONValue(obj, i)
		valueRaw := obj[i:valueEnd]
		i = valueEnd

		var key string
		switch {
		case !keyEscaped:
			key = keyRaw[1 : len(keyRaw)-1]
		case len(keyRaw) <= sessionPayloadMaxKeyRaw:
			key = gjson.Parse(keyRaw).Str
		default:
			continue
		}
		raw := valueRaw
		nested := false
		_, wanted := sessionPayloadKeys[key]
		switch {
		case wanted:
		case top && key == sessionPayloadContentsKey:
			raw = "null"
		case top && key == sessionPayloadRequestKey:
			nested = valueRaw[0] == '{'
		default:
			continue
		}
		sep := ","
		if first {
			sep = ""
		}
		first = false
		if nested {
			if !b.add(sep, keyRaw, ":") || !b.appendObject(valueRaw, false) {
				return false
			}
		} else if !b.add(sep, keyRaw, ":", raw) {
			return false
		}
	}
	return b.add("}")
}

func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// scanJSONString returns the index just past the string starting at s[i] == '"'
// and whether it contains escapes.
func scanJSONString(s string, i int) (int, bool) {
	escaped := false
	for i++; i < len(s); i++ {
		switch s[i] {
		case '\\':
			escaped = true
			i++
		case '"':
			return i + 1, escaped
		}
	}
	return len(s), escaped
}

// scanJSONValue returns the index just past the valid JSON value starting at s[i].
func scanJSONValue(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch s[i] {
	case '"':
		end, _ := scanJSONString(s, i)
		return end
	case '{', '[':
		depth := 0
		for i < len(s) {
			switch s[i] {
			case '"':
				i, _ = scanJSONString(s, i)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return i
	default:
		for i < len(s) {
			switch s[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
			i++
		}
		return i
	}
}

type sessionProjectionKey struct {
	n   int
	sum uint64
}

// sessionProjectionEntry pairs a private copy of the payload bytes with their
// projection. The key hash is only a lookup hint; body is compared byte for byte
// before view is reused. A fallback entry holds no body and no view: it only
// tells the caller to read its own payload directly.
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
	if entry, ok := c.get(key); ok {
		// A fallback hit, even on a hash collision, only makes the caller read
		// payload itself, so it is safe without comparing bytes.
		if entry.fallback {
			return payload
		}
		if bytes.Equal(entry.body, payload) {
			return entry.view
		}
	}
	if sessionProjectionBuildObserver != nil {
		sessionProjectionBuildObserver()
	}
	view, ok := projectSessionPayload(payload)
	if !ok {
		c.put(key, sessionProjectionEntry{fallback: true})
		return payload
	}
	c.put(key, sessionProjectionEntry{body: bytes.Clone(payload), view: view})
	return view
}

// sessionProjectionBuildObserver is a test hook called whenever the cache builds
// a projection. It is nil in production.
var sessionProjectionBuildObserver func()

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
