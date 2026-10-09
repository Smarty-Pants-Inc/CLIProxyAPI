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
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
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

func TestSessionProjectionCacheBounded(t *testing.T) {
	c := &sessionProjectionCache{entries: make(map[sessionProjectionKey]sessionProjectionEntry)}
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
