package session

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

var (
	projectionMismatchMu sync.Mutex
	projectionMismatches []string
)

// TestMain turns every ExtractSessionInfo call made by this package's tests
// (including the pre-existing fixtures) into an equivalence check between the
// projected payload view and the full payload.
func TestMain(m *testing.M) {
	sessionPayloadViewObserver = func(headers http.Header, payload []byte, metadata map[string]any, info SessionInfo, ok bool) {
		if msg := compareProjection(headers, payload, metadata, info, ok); msg != "" {
			projectionMismatchMu.Lock()
			projectionMismatches = append(projectionMismatches, msg)
			projectionMismatchMu.Unlock()
		}
	}
	code := m.Run()
	if len(projectionMismatches) > 0 {
		fmt.Fprintf(os.Stderr, "session payload projection mismatches (%d):\n", len(projectionMismatches))
		for i, msg := range projectionMismatches {
			if i == 20 {
				break
			}
			fmt.Fprintln(os.Stderr, msg)
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func compareProjection(headers http.Header, payload []byte, metadata map[string]any, info SessionInfo, ok bool) string {
	wantInfo, wantOK := extractSessionInfo(headers, payload, metadata)
	if ok != wantOK || !reflect.DeepEqual(info, wantInfo) {
		return fmt.Sprintf("ExtractSessionInfo mismatch\n headers=%v\n payload=%.300q\n got=%+v,%v\n want=%+v,%v", headers, payload, info, ok, wantInfo, wantOK)
	}
	view := sessionPayloadView(payload)
	if got, want := hasExplicitPayloadSession(view), hasExplicitPayloadSession(payload); got != want {
		return fmt.Sprintf("hasExplicitPayloadSession mismatch payload=%.300q got=%v want=%v", payload, got, want)
	}
	gotSID, gotParent, gotAgent := ClaudeMetadataIdentities(view)
	wantSID, wantParent, wantAgent := ClaudeMetadataIdentities(payload)
	if gotSID != wantSID || gotParent != wantParent || gotAgent != wantAgent {
		return fmt.Sprintf("ClaudeMetadataIdentities mismatch payload=%.300q", payload)
	}
	return ""
}

func assertProjectionEquivalent(t *testing.T, headers http.Header, payload []byte, metadata map[string]any) {
	t.Helper()
	info, ok := ExtractSessionInfo(headers, payload, metadata)
	if msg := compareProjection(headers, payload, metadata, info, ok); msg != "" {
		t.Fatal(msg)
	}
}

// sessionTestPaths is every payload path read by session extraction.
var sessionTestPaths = []string{
	"parent_session_id", "parentSessionId", "parentSessionID", "parent_thread_id", "parentThreadId", "parentThreadID",
	"forked_from_thread_id", "forked_from_id", "parent_conversation_id", "parentConversationId", "parentConversationID",
	"parent_id", "parentId", "parentID", "parent_task_id", "parentTaskId", "parentTaskID",
	"parent_action_id", "parentActionId", "parentActionID", "parent_session", "parentSession",
	"parent_subagent_id", "parentSubagentId", "forkSource.sessionId", "fork_source.session_id",
	"previousSessionId", "previous_session_id",
	"metadata.parent_session_id", "metadata.parentSessionId", "metadata.parent_thread_id", "metadata.forked_from_id",
	"metadata.parent_id", "metadata.parent_task_id", "metadata.parent_agent_id", "metadata.parentAgentId",
	"metadata.forkSource.sessionId", "metadata.previousSessionId",
	"extra_body.parent_session_id", "extra_body.parent_id", "extra_body.forked_from_thread_id", "extra_body.forkSource.sessionId",
	"metadata.agent_id", "metadata.subagent_id",
	"thread_id", "threadId", "metadata.thread_id", "cachedContent", "cached_content",
	"session_id", "sessionId", "sessionID", "child_session_id", "childSessionId",
	"metadata.session_id", "metadata.sessionId", "metadata.child_session_id", "extra_body.session_id",
	"task_id", "taskId", "taskID", "action_id", "actionId", "actionID", "metadata.task_id", "metadata.action_id", "extra_body.task_id",
	"conversation.id", "conversation", "prompt_cache_key", "promptCacheKey",
	"metadata.user_id", "conversation_id", "conversationId", "chat_id", "chatId", "metadata.conversation_id", "extra_body.conversation_id",
}

func jsonAtPath(path, value string) string {
	parts := strings.Split(path, ".")
	out := strconv.Quote(value)
	for i := len(parts) - 1; i >= 0; i-- {
		out = `{` + strconv.Quote(parts[i]) + `:` + out + `}`
	}
	return out[1 : len(out)-1]
}

func padMessages(n int) string {
	var b strings.Builder
	b.WriteString(`"messages":[`)
	for i := 0; b.Len() < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// Messages deliberately contain session-like keys that must never be read.
		fmt.Fprintf(&b, `{"role":"user","session_id":"inner-%d","metadata":{"user_id":"inner"},"content":"x \"}{][ %d"}`, i, i)
	}
	b.WriteString(`]`)
	return b.String()
}

func projectionPayloadFixtures() [][]byte {
	var out [][]byte
	add := func(s string) { out = append(out, []byte(s)) }
	add(`{}`)
	add(`{"messages":[{"role":"user","content":"hi"}]}`)
	for i, p := range sessionTestPaths {
		member := jsonAtPath(p, "v-"+strings.ReplaceAll(p, ".", "-"))
		parent := jsonAtPath(sessionTestPaths[(i+7)%len(sessionTestPaths)], "parent-x")
		add(`{` + member + `}`)
		add(`{` + padMessages(256) + `,` + member + `,` + parent + `}`)
		add(`{"request":{` + member + `,` + padMessages(128) + `}}`)
		add(`{"contents":[{"parts":[{"text":"x"}]}],"request":{` + member + `}}`)
		add(`{` + member + `,"request":{` + parent + `}}`)
	}
	claudeUserIDs := []string{
		`{\"session_id\":\"s-1\"}`,
		`{\"session_id\":\"s-1\",\"parent_session_id\":\"p-1\",\"agent_id\":\"a-1\"}`,
		`{\"session_id\":\"s-1\",\"parent_agent_id\":\"pa-1\",\"subagent_id\":\"sa-1\"}`,
		`user_abc_account_def_session_0b5c0bd6-6e6a-4f7a-9a51-3c0f4c2c9d11`,
		`plain-user`,
	}
	for _, uid := range claudeUserIDs {
		add(`{` + padMessages(512) + `,"metadata":{"user_id":"` + uid + `","agent_id":"ag","parent_agent_id":"pag"}}`)
		add(`{"metadata":{"user_id":"` + uid + `"},"session_id":"body-sid","parent_id":"body-parent"}`)
		add(`{"request":{"metadata":{"user_id":"` + uid + `","parent_session_id":"np"}},"model":"gemini"}`)
	}
	// Large body (> cache threshold) with messages first and metadata last.
	add(`{` + padMessages(64<<10) + `,"system":"sys","metadata":{"user_id":"{\"session_id\":\"big-1\",\"parent_session_id\":\"big-p\"}"}}`)
	add(`{` + padMessages(64<<10) + `,"prompt_cache_key":"pck-big","conversation":{"id":"conv-big"},"parent_id":"pp"}`)
	add(`{"contents":[` + strings.Repeat(`{"parts":[{"text":"aaaaaaaaaaaaaaaa"}]},`, 4096) + `{}],"request":{"session_id":"ignored"},"cachedContent":"cc-big"}`)
	// Duplicate keys, escaped keys, odd value types and whitespace.
	add(`{"metadata":{"agent_id":"a"},"metadata":{"user_id":"{\"session_id\":\"dup\"}"},"session_id":"s1","session_id":"s2"}`)
	add(`{"meta\u0064ata":{"session_id":"escaped"},"session\u005fid":"esc-sid"}`)
	add(` { "conversation" : "conv-str" , "thread_id" : 42 , "request" : "not-an-object" } `)
	add(`{"conversation":{"id":7},"task_id":null,"forkSource":{"sessionId":"fork-1"},"session_id":"s"}`)
	add(`{"thread_id":"t","forked_from_id":"f","parent_id":"p","request":{"forkSource":{"sessionId":"x"}}}`)
	add(`{"request":{"session_id":"nested"},"request":{"parent_id":"nested-parent"}}`)
	add(`{"session_id":"sid\u0000ctrl","parent_id":"` + strings.Repeat("x", 300) + `"}`)
	// Scanner edge cases: escaped quotes and brackets inside strings, literals,
	// escaped and over-long escaped keys, and arrays of objects before members.
	add(`{"messages":[{"a":"}]\"{["},[1,{"b":[]}]],"session_id":"a\"b\\","metadata":{"x":"}]{[","user_id":"u\\"}}`)
	add(`{"thread_id":true,"session_id":-1.5e3,"task_id":false,"chat_id":null,"conversation":["c"]}`)
	add(`{"\u0073ession_id":"esc-key","` + strings.Repeat(`\u0073`, 40) + `":"long-esc","conversation_id":"cid"}`)
	add("{\n\t\"request\" :\r\n {\"session_id\" : \"ws\" , \"contents\":[]} ,\n\"model\":\"m\"\n}\n")
	add(`{"request":{},"request":[],"contents":"","session_id":""}`)
	// Not valid JSON objects: must be read exactly as before.
	add(`[{"session_id":"array"}]`)
	add(`"session_id"`)
	add(`{"session_id":"truncated","messages":[{"role":"user"`)
	add(`{"messages":[}],"session_id":"bad-inner"}`)
	add(`{"session_id":"trailing"} garbage`)
	add(`   `)
	return out
}

func projectionHeaderFixtures() []http.Header {
	return []http.Header{
		nil,
		{},
		{"X-Claude-Code-Session-Id": {"claude-sid"}},
		{"X-Claude-Code-Session-Id": {"claude-sid"}, "X-Claude-Code-Agent-Id": {"agent-h"}, "X-Claude-Code-Parent-Agent-Id": {"parent-agent-h"}},
		{"X-Claude-Code-Agent-Id": {"agent-h"}},
		{"Session-Id": {"codex-sid"}},
		{"Session_id": {"codex-sid"}, "Thread-Id": {"codex-tid"}},
		{"Session-Id": {"codex-sid"}, "X-Openai-Subagent": {"review"}},
		{"X-Codex-Turn-Metadata": {`{"session_id":"tm-s","thread_id":"tm-t","agent_name":"/root/worker","subagent_kind":"thread_spawn"}`}},
		{"Session-Id": {"codex-sid"}, "X-Codex-Turn-Metadata": {`{"forked_from_thread_id":"tm-fork"}`}},
		{"X-Http-Session-Id": {"agy-sid"}},
		{"X-Session-ID": {"gen-sid"}, "X-Parent-Session-ID": {"gen-parent"}},
		{"X-Session-Affinity": {"aff"}},
		{"X-Slot-Session-Id": {"slot"}},
		{"X-Task-ID": {"task"}},
		{"X-Conversation-Id": {"conv"}},
		{"X-Thread-Id": {"thr"}},
		{"X-Client-Request-Id": {"creq"}},
		{"x-agent-id": {"xagent"}},
	}
}

func projectionMetadataFixtures() []map[string]any {
	return []map[string]any{
		nil,
		{cliproxyexecutor.CallerScopeMetadataKey: " scope "},
		{cliproxyexecutor.ExecutionSessionMetadataKey: "exec-1"},
		{cliproxyexecutor.LCPAffinitySessionIDMetadataKey: "lcp:v1:abc", cliproxyexecutor.ParentSessionIDMetadataKey: "lcp:v1:parent", cliproxyexecutor.IsCompactionMetadataKey: true},
		{cliproxyexecutor.LCPAffinitySessionIDMetadataKey: "lcp:v1:abc", cliproxyexecutor.ParentSessionIDMetadataKey: "lcp:v1:parent"},
	}
}

func TestSessionPayloadViewEquivalence(t *testing.T) {
	payloads := append(projectionPayloadFixtures(), nil)
	for _, payload := range payloads {
		for _, headers := range projectionHeaderFixtures() {
			for _, metadata := range projectionMetadataFixtures() {
				assertProjectionEquivalent(t, headers, payload, metadata)
			}
		}
	}
}

// referenceSessionProjection is the original gjson ForEach based projection,
// without a size bound; the in-place scanner must produce identical bytes.
func referenceSessionProjection(payload []byte) ([]byte, bool) {
	if !gjson.ValidBytes(payload) {
		return nil, false
	}
	root := gjson.ParseBytes(payload)
	if !root.IsObject() {
		return nil, false
	}
	var appendObj func(dst []byte, obj gjson.Result, top bool) []byte
	appendObj = func(dst []byte, obj gjson.Result, top bool) []byte {
		dst = append(dst, '{')
		first := true
		obj.ForEach(func(key, value gjson.Result) bool {
			raw, nested := value.Raw, false
			_, wanted := sessionPayloadKeys[key.Str]
			switch {
			case wanted:
			case top && key.Str == sessionPayloadContentsKey:
				raw = "null"
			case top && key.Str == sessionPayloadRequestKey:
				nested = value.IsObject()
			default:
				return true
			}
			if !first {
				dst = append(dst, ',')
			}
			first = false
			dst = append(append(dst, key.Raw...), ':')
			if nested {
				dst = appendObj(dst, value, false)
			} else {
				dst = append(dst, raw...)
			}
			return true
		})
		return append(dst, '}')
	}
	return appendObj(nil, root, true), true
}

func TestSessionProjectionMatchesReference(t *testing.T) {
	for _, payload := range projectionPayloadFixtures() {
		got, ok := projectSessionPayload(payload)
		want, wantOK := referenceSessionProjection(payload)
		if ok != wantOK || !bytes.Equal(got, want) {
			t.Fatalf("projection mismatch for %.200q:\n got %q,%v\nwant %q,%v", payload, got, ok, want, wantOK)
		}
	}
}

// TestSessionProjectionBoundAtCap checks the projection is built up to exactly
// the cap and aborted one byte past it.
func TestSessionProjectionBoundAtCap(t *testing.T) {
	frame := len(`{"session_id":""}`)
	for _, extra := range []int{0, 1} {
		value := strings.Repeat("v", sessionProjectionCacheMaxProjection-frame+extra)
		payload := []byte(`{` + padMessages(1024) + `,"session_id":"` + value + `"}`)
		view, ok := projectSessionPayload(payload)
		if extra == 0 && (!ok || len(view) != sessionProjectionCacheMaxProjection || string(view) != `{"session_id":"`+value+`"}`) {
			t.Fatalf("projection at the cap: ok=%v len=%d", ok, len(view))
		}
		if extra == 1 && ok {
			t.Fatalf("projection one byte over the cap was built (len %d)", len(view))
		}
		if got := sessionPayloadView(payload); extra == 1 && unsafe.SliceData(got) != unsafe.SliceData(payload) {
			t.Fatal("oversize projection must fall back to the original payload")
		}
		assertProjectionEquivalent(t, http.Header{}, payload, nil)
	}
}

// bigEscapedString is an n-byte JSON string body full of escapes, so a reader
// that unescapes it (as gjson does for string values it visits) must copy it.
func bigEscapedString(n int) string {
	return strings.Repeat(`ab\n\"cd\\`, n/10)
}

func allocatedBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestSessionProjectionOversizeValuesFallBackWithoutCopy covers the security
// fix: a client-controlled huge value under a projected key must not be copied
// by the projection (neither into the projection nor into a cached body copy),
// extraction must equal the legacy path, and later calls on the same payload
// must not rebuild the aborted projection.
func TestSessionProjectionOversizeValuesFallBackWithoutCopy(t *testing.T) {
	const big = 10 << 20
	const allocBound = 2 * sessionProjectionCacheMaxProjection
	blob := bigEscapedString(big)
	userID := `"user_id":"{\"session_id\":\"meta-sid\",\"parent_session_id\":\"meta-parent\"}"`
	bigMetadata := []byte(`{"model":"m","messages":[],"metadata":{` + userID + `,"blob":"` + blob + `"},"conversation_id":"cid"}`)
	bigSessionID := []byte(`{"model":"m","session_id":"` + blob + `","metadata":{` + userID + `}}`)
	bigBoth := []byte(`{"metadata":{` + userID + `,"blob":"` + blob + `"},"session_id":"` + blob + `","messages":[]}`)
	if len(bigMetadata) > sessionProjectionCacheMaxPayload || len(bigSessionID) > sessionProjectionCacheMaxPayload || len(bigBoth) <= sessionProjectionCacheMaxPayload {
		t.Fatal("fixtures: single-value payloads must be cacheable, the combined one must not")
	}

	for name, payload := range map[string][]byte{"metadata": bigMetadata, "session_id": bigSessionID, "both": bigBoth} {
		t.Run(name, func(t *testing.T) {
			var ok bool
			if n := allocatedBytes(func() { _, ok = projectSessionPayload(payload) }); ok || n > allocBound {
				t.Fatalf("projection build: ok=%v allocated %d bytes, want abort within %d", ok, n, allocBound)
			}

			c := newSessionProjectionCache()
			builds := 0
			sessionProjectionBuildObserver = func() { builds++ }
			defer func() { sessionProjectionBuildObserver = nil }()
			for i := 0; i < 3; i++ {
				var view []byte
				if n := allocatedBytes(func() { view = c.view(payload) }); n > allocBound {
					t.Fatalf("call %d: view allocated %d bytes (body copied?)", i, n)
				}
				if unsafe.SliceData(view) != unsafe.SliceData(payload) {
					t.Fatalf("call %d: oversize projection did not fall back to the original payload", i)
				}
			}
			if len(payload) > sessionProjectionCacheMaxPayload {
				// Never cached; each call is a bounded, aborted build.
				if c.count != 0 || c.bytes != 0 {
					t.Fatalf("uncacheable payload cached: count=%d bytes=%d", c.count, c.bytes)
				}
			} else {
				if builds != 1 {
					t.Fatalf("projection built %d times for one payload, want 1", builds)
				}
				entry, found := c.get(sessionProjectionKey{n: len(payload), sum: c.sum(payload)})
				if !found || !entry.fallback || entry.body != nil || entry.view != nil || c.bytes != 0 {
					t.Fatalf("fallback entry = %+v found=%v bytes=%d; want a body-less marker", entry, found, c.bytes)
				}
				if allocs := testing.AllocsPerRun(5, func() { c.view(payload) }); allocs != 0 {
					t.Fatalf("cached fallback allocated %v times per call", allocs)
				}
			}

			for _, headers := range []http.Header{{}, {"X-Claude-Code-Session-Id": {"hdr"}}} {
				assertProjectionEquivalent(t, headers, payload, nil)
			}
		})
	}
}

// TestSessionProjectionFallbackCollisionIsSafe checks that a fallback marker hit
// by a different payload under the same key only sends it to the legacy path.
func TestSessionProjectionFallbackCollisionIsSafe(t *testing.T) {
	saved := sessionProjections
	sessionProjections = collidingProjectionCache()
	defer func() { sessionProjections = saved }()
	pad := padMessages(32 << 10)
	invalid := []byte(`{` + pad + `,"metadata":{"user_id":"{\"session_id\":\"coll-a\"}"}`)
	valid := []byte(`{` + pad + `,"metadata":{"user_id":"{\"session_id\":\"coll-b\"}"}}`)
	invalid = append(invalid, ' ') // truncated JSON padded to the same length as valid
	if len(invalid) != len(valid) {
		t.Fatalf("fixture lengths %d vs %d", len(invalid), len(valid))
	}
	if view := sessionPayloadView(invalid); unsafe.SliceData(view) != unsafe.SliceData(invalid) {
		t.Fatal("invalid payload should be read directly")
	}
	if view := sessionPayloadView(valid); unsafe.SliceData(view) != unsafe.SliceData(valid) {
		t.Fatal("colliding payload should be read directly via the fallback marker")
	}
	if info, ok := ExtractSessionInfo(http.Header{}, valid, nil); !ok || info.SessionID != "claude:coll-b" {
		t.Fatalf("colliding payload info = %+v, %v", info, ok)
	}
}

func TestSessionPayloadViewDropsHeavyMembers(t *testing.T) {
	payload := largeClaudeBody(256 << 10)
	view := sessionPayloadView(payload)
	if len(view) > 512 {
		t.Fatalf("view too large (%d bytes): %.200s", len(view), view)
	}
	want := `{"metadata":{"user_id":"{\"device_id\":\"dev\",\"account_uuid\":\"acct\",\"session_id\":\"0b5c0bd6-6e6a-4f7a-9a51-3c0f4c2c9d11\"}"}}`
	if string(view) != want {
		t.Fatalf("view = %s, want %s", view, want)
	}
	nested := []byte(`{"model":"m","request":{"contents":[{"parts":[{"text":"x"}]}],"session_id":"s","request":{"a":1}},"contents":[1]}`)
	if got, want := string(sessionPayloadView(nested)), `{"request":{"session_id":"s"},"contents":null}`; got != want {
		t.Fatalf("nested view = %s, want %s", got, want)
	}
	for _, invalid := range []string{`[1]`, `{"a":`, `nope`} {
		if got := sessionPayloadView([]byte(invalid)); string(got) != invalid {
			t.Fatalf("invalid payload %q should pass through, got %q", invalid, got)
		}
	}
}

func TestSessionPayloadViewCacheReuseAndInvalidation(t *testing.T) {
	headers := http.Header{}
	payload := []byte(`{` + padMessages(64<<10) + `,"metadata":{"user_id":"{\"session_id\":\"cache-a\"}"}}`)

	first := sessionPayloadView(payload)
	second := sessionPayloadView(payload)
	if unsafe.SliceData(first) != unsafe.SliceData(second) {
		t.Fatal("second view of the same payload was not served from the cache")
	}
	// A clone with identical bytes is the same request input and may share the projection.
	if clone := sessionPayloadView(bytes.Clone(payload)); unsafe.SliceData(clone) != unsafe.SliceData(first) {
		t.Fatal("identical payload bytes should reuse the cached projection")
	}
	info, ok := ExtractSessionInfo(headers, payload, nil)
	if !ok || info.SessionID != "claude:cache-a" {
		t.Fatalf("first request info = %+v, %v", info, ok)
	}

	// A different payload (e.g. a translated body) must not see the cached value.
	other := bytes.Replace(payload, []byte("cache-a"), []byte("cache-b"), 1)
	if view := sessionPayloadView(other); unsafe.SliceData(view) == unsafe.SliceData(first) {
		t.Fatal("different payload reused a stale projection")
	}
	if info, ok = ExtractSessionInfo(headers, other, nil); !ok || info.SessionID != "claude:cache-b" {
		t.Fatalf("different payload info = %+v, %v", info, ok)
	}

	// In-place mutation of the same slice is also a different input.
	copy(payload[bytes.Index(payload, []byte("cache-a")):], "cache-c")
	if info, ok = ExtractSessionInfo(headers, payload, nil); !ok || info.SessionID != "claude:cache-c" {
		t.Fatalf("mutated payload info = %+v, %v", info, ok)
	}

	// Nil payload falls back to headers/metadata only.
	if info, ok = ExtractSessionInfo(headers, nil, nil); ok {
		t.Fatalf("nil payload must not reuse a cached payload identity: %+v", info)
	}
	if info, ok = ExtractSessionInfo(http.Header{"X-Session-ID": {"hdr"}}, nil, nil); !ok || info.SessionID != "header:hdr" {
		t.Fatalf("nil payload with header info = %+v, %v", info, ok)
	}

	// Headers and metadata are re-evaluated on every call even when the payload view is cached.
	if info, ok = ExtractSessionInfo(http.Header{"X-Claude-Code-Session-Id": {"hdr-claude"}}, payload, nil); !ok || info.SessionID != "claude:hdr-claude" {
		t.Fatalf("header change ignored: %+v, %v", info, ok)
	}
	if info, ok = ExtractSessionInfo(headers, payload, map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "scope-x"}); !ok || info.CallerScope != "scope-x" {
		t.Fatalf("metadata change ignored: %+v, %v", info, ok)
	}
}

// collidingProjectionCache returns a cache whose hash maps every payload to the
// same value, so any two same-length payloads share a lookup key.
func collidingProjectionCache() *sessionProjectionCache {
	c := newSessionProjectionCache()
	c.hash = func([]byte) uint64 { return 42 }
	return c
}

func TestSessionProjectionCacheVerifiesBytesOnCollision(t *testing.T) {
	c := collidingProjectionCache()
	a := []byte(`{` + padMessages(64<<10) + `,"metadata":{"user_id":"{\"session_id\":\"coll-a\"}"}}`)
	b := bytes.Replace(a, []byte("coll-a"), []byte("coll-b"), 1)
	if len(a) != len(b) || bytes.Equal(a, b) {
		t.Fatal("fixture must be two different same-length payloads")
	}
	wantA, _ := projectSessionPayload(a)
	wantB, _ := projectSessionPayload(b)

	if got := c.view(a); !bytes.Equal(got, wantA) {
		t.Fatalf("view(a) = %q, want %q", got, wantA)
	}
	if got := c.view(b); !bytes.Equal(got, wantB) {
		t.Fatalf("colliding payload b got another body's projection: %q, want %q", got, wantB)
	}
	// The mismatch replaced the entry rather than adding a second one.
	if c.count != 1 || len(c.entries) != 1 || c.bytes != len(b)+len(wantB) {
		t.Fatalf("after replacement count=%d entries=%d bytes=%d", c.count, len(c.entries), c.bytes)
	}
	if got := c.view(a); !bytes.Equal(got, wantA) {
		t.Fatalf("view(a) after collision = %q, want %q", got, wantA)
	}
	// In-place mutation of a cached caller slice is caught by the private copy.
	copy(a[bytes.Index(a, []byte("coll-a")):], "coll-c")
	wantC, _ := projectSessionPayload(a)
	if got := c.view(a); !bytes.Equal(got, wantC) {
		t.Fatalf("mutated payload got a stale projection: %q, want %q", got, wantC)
	}

	// End to end: session IDs resolved through the colliding package cache.
	saved := sessionProjections
	sessionProjections = collidingProjectionCache()
	defer func() { sessionProjections = saved }()
	for _, tc := range []struct {
		payload []byte
		want    string
	}{{b, "claude:coll-b"}, {a, "claude:coll-c"}, {b, "claude:coll-b"}} {
		if info, ok := ExtractSessionInfo(http.Header{}, tc.payload, nil); !ok || info.SessionID != tc.want {
			t.Fatalf("ExtractSessionInfo = %+v, %v; want %s", info, ok, tc.want)
		}
	}
}

func TestSessionProjectionCacheByteBudgetEvicts(t *testing.T) {
	c := newSessionProjectionCache()
	entry := sessionProjectionEntry{body: make([]byte, 1000), view: []byte("{}")}
	c.maxBytes = 3 * entry.size()
	for i := 0; i < 5; i++ {
		c.put(sessionProjectionKey{n: 1000, sum: uint64(i)}, entry)
	}
	if c.bytes > c.maxBytes || c.count != 3 || len(c.entries) != 3 || c.bytes != 3*entry.size() {
		t.Fatalf("bytes=%d (max %d) count=%d entries=%d", c.bytes, c.maxBytes, c.count, len(c.entries))
	}
	for i := 0; i < 5; i++ {
		_, ok := c.get(sessionProjectionKey{n: 1000, sum: uint64(i)})
		if want := i >= 2; ok != want {
			t.Fatalf("entry %d present=%v, want %v", i, ok, want)
		}
	}
	// A single entry larger than the whole budget is not cached and evicts nothing.
	c.put(sessionProjectionKey{n: 1, sum: 99}, sessionProjectionEntry{body: make([]byte, c.maxBytes+1)})
	if _, ok := c.get(sessionProjectionKey{n: 1, sum: 99}); ok || c.count != 3 {
		t.Fatalf("over-budget entry cached or evicted others: count=%d", c.count)
	}
	// The default budget is the documented 64 MiB.
	if got := newSessionProjectionCache().maxBytes; got != 64<<20 {
		t.Fatalf("default byte budget = %d", got)
	}
}

func TestSessionProjectionCacheSkipsOversizePayloads(t *testing.T) {
	c := newSessionProjectionCache()
	prefix := `{"metadata":{"user_id":"{\"session_id\":\"big\"}"},"messages":"`
	payload := []byte(prefix + strings.Repeat("x", sessionProjectionCacheMaxPayload-len(prefix)) + `"}`)
	if len(payload) <= sessionProjectionCacheMaxPayload {
		t.Fatal("fixture must exceed the cacheable payload size")
	}
	want, _ := projectSessionPayload(payload)
	for i := 0; i < 2; i++ {
		if got := c.view(payload); !bytes.Equal(got, want) {
			t.Fatalf("oversize view = %q, want %q", got, want)
		}
	}
	if c.count != 0 || len(c.entries) != 0 || c.bytes != 0 {
		t.Fatalf("oversize payload was cached: count=%d bytes=%d", c.count, c.bytes)
	}
	// Exactly at the limit is still cacheable.
	atLimit := payload[:0:0]
	atLimit = append(atLimit, prefix...)
	atLimit = append(atLimit, strings.Repeat("x", sessionProjectionCacheMaxPayload-len(prefix)-2)...)
	atLimit = append(atLimit, `"}`...)
	c.view(atLimit)
	if len(atLimit) != sessionProjectionCacheMaxPayload || c.count != 1 {
		t.Fatalf("payload at limit (len %d) not cached: count=%d", len(atLimit), c.count)
	}
}

func TestSessionProjectionCacheBounded(t *testing.T) {
	c := newSessionProjectionCache()
	for i := 0; i < 3*sessionProjectionCacheEntries; i++ {
		c.put(sessionProjectionKey{n: i, sum: uint64(i)}, sessionProjectionEntry{view: []byte("{}")})
	}
	if len(c.entries) != sessionProjectionCacheEntries {
		t.Fatalf("cache size = %d, want %d", len(c.entries), sessionProjectionCacheEntries)
	}
	if _, ok := c.get(sessionProjectionKey{n: 3*sessionProjectionCacheEntries - 1, sum: uint64(3*sessionProjectionCacheEntries - 1)}); !ok {
		t.Fatal("most recent entry evicted")
	}
	if _, ok := c.get(sessionProjectionKey{n: 0, sum: 0}); ok {
		t.Fatal("oldest entry not evicted")
	}
}

// TestSessionPayloadKeysCoverAllReadPaths parses the payload readers and checks
// that the first segment of every literal JSON path they read is kept by the projection.
func TestSessionPayloadKeysCoverAllReadPaths(t *testing.T) {
	readers := map[string]bool{
		"extractSessionInfo": true, "isBodyForkCandidate": true,
		"ClaudeMetadataIdentities": true, "hasExplicitPayloadSession": true,
	}
	gjsonReceivers := map[string]bool{"root": true, "reqRoot": true, "req": true}
	fset := token.NewFileSet()
	seen := 0
	for _, file := range []string{"info.go", "identity.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !readers[fn.Name.Name] {
				continue
			}
			seen++
			check := func(lit *ast.BasicLit, receiver string) {
				path, err := strconv.Unquote(lit.Value)
				if err != nil || path == "" || strings.Contains(path, "-") || (path[0] >= 'A' && path[0] <= 'Z') {
					return // header names, not payload paths
				}
				first := strings.SplitN(path, ".", 2)[0]
				if _, ok := sessionPayloadKeys[first]; ok {
					return
				}
				if receiver == "root" && (first == sessionPayloadRequestKey || first == sessionPayloadContentsKey) {
					return
				}
				t.Errorf("%s reads payload path %q (receiver %q) whose top-level key is not projected", fn.Name.Name, path, receiver)
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					sel, ok := node.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "Get" || len(node.Args) != 1 {
						return true
					}
					recv, ok := sel.X.(*ast.Ident)
					if !ok || !gjsonReceivers[recv.Name] {
						return true
					}
					if lit, ok := node.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						check(lit, recv.Name)
					}
				case *ast.RangeStmt:
					comp, ok := node.X.(*ast.CompositeLit)
					if !ok {
						return true
					}
					for _, elt := range comp.Elts {
						if lit, ok := elt.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							check(lit, "range")
						}
					}
				}
				return true
			})
		}
	}
	if seen != len(readers) {
		t.Fatalf("found %d of %d reader functions", seen, len(readers))
	}
}
