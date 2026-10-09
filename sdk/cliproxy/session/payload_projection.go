package session

import (
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
// Memoization rule: the view is a pure function of the payload bytes, so it is
// cached by payload length plus a per-process seeded 64-bit hash of the full
// content, never by slice identity alone. Repeat calls for the same request (the
// handler, session.Enrich and the auth selector all pass the same body) reuse
// one projection; a different payload (a translated or interceptor-rewritten
// body, or nil) hashes differently and is projected afresh. Headers and metadata
// are never cached and are always evaluated by the caller on every call.
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
	key := sessionProjectionKey{n: len(payload), sum: maphash.Bytes(sessionProjections.seed, payload)}
	if entry, ok := sessionProjections.get(key); ok {
		if entry.fallback {
			return payload
		}
		return entry.view
	}
	view, ok := projectSessionPayload(payload)
	if !ok {
		sessionProjections.put(key, sessionProjectionEntry{fallback: true})
		return payload
	}
	if len(view) <= sessionProjectionCacheMaxProjection {
		sessionProjections.put(key, sessionProjectionEntry{view: view})
	}
	return view
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

type sessionProjectionEntry struct {
	view     []byte
	fallback bool
}

type sessionProjectionCache struct {
	seed    maphash.Seed
	mu      sync.Mutex
	entries map[sessionProjectionKey]sessionProjectionEntry
	ring    [sessionProjectionCacheEntries]sessionProjectionKey
	used    [sessionProjectionCacheEntries]bool
	next    int
}

var sessionProjections = &sessionProjectionCache{
	seed:    maphash.MakeSeed(),
	entries: make(map[sessionProjectionKey]sessionProjectionEntry, sessionProjectionCacheEntries),
}

func (c *sessionProjectionCache) get(key sessionProjectionKey) (sessionProjectionEntry, bool) {
	c.mu.Lock()
	entry, ok := c.entries[key]
	c.mu.Unlock()
	return entry, ok
}

func (c *sessionProjectionCache) put(key sessionProjectionKey, entry sessionProjectionEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; exists {
		c.entries[key] = entry
		return
	}
	if c.used[c.next] {
		delete(c.entries, c.ring[c.next])
	}
	c.ring[c.next] = key
	c.used[c.next] = true
	c.next = (c.next + 1) % sessionProjectionCacheEntries
	c.entries[key] = entry
}
