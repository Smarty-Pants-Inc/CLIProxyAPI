package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// CLIProxyAPI#111 final round.

const (
	finalRoundClientAKey = "client-a-own-cache-key"
	finalRoundClientBKey = "client-b-own-cache-key"
)

func finalRoundState(original string) codexIdentityConfuseState {
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", original)
	return codexIdentityConfuseState{
		enabled:                true,
		authID:                 identityTestAuthID,
		originalPromptCacheKey: original,
		promptCacheKey:         confused,
		ruleKeyFrom:            confused,
		ruleKey:                identityTestOperatorKey,
	}
}

// A rejection whose owner is unknown must not restore a shared rule key to any
// one request's original, and only unambiguous remapped values are restored.
func TestCodexUnassignedRejectionNeverCrossesClients(t *testing.T) {
	stateA, stateB := finalRoundState(finalRoundClientAKey), finalRoundState(finalRoundClientBKey)
	states := []codexIdentityConfuseState{stateA, stateB}

	shared := []byte(`{"type":"error","error":{"message":"rejected prompt_cache_key ` + identityTestOperatorKey + `"}}`)
	got := string(exposeCodexUnassignedIdentity(shared, states))
	if strings.Contains(got, finalRoundClientAKey) || strings.Contains(got, finalRoundClientBKey) {
		t.Fatalf("shared rule key was restored to one client's key: %s", got)
	}
	if !strings.Contains(got, identityTestOperatorKey) {
		t.Fatalf("operator rule key was rewritten: %s", got)
	}

	ownA := []byte(`{"type":"error","error":{"message":"rejected ` + stateA.promptCacheKey + `"}}`)
	if got := string(exposeCodexUnassignedIdentity(ownA, states)); !strings.Contains(got, finalRoundClientAKey) || strings.Contains(got, finalRoundClientBKey) || strings.Contains(got, stateA.promptCacheKey) {
		t.Fatalf("unambiguous remapped key not restored to its own original only: %s", got)
	}

	// The same remapped value claimed by two originals is left alone.
	conflicting := stateB
	conflicting.promptCacheKey = stateA.promptCacheKey
	got = string(exposeCodexUnassignedIdentity(ownA, []codexIdentityConfuseState{stateA, conflicting}))
	if strings.Contains(got, finalRoundClientAKey) || strings.Contains(got, finalRoundClientBKey) || !strings.Contains(got, stateA.promptCacheKey) {
		t.Fatalf("ambiguous remapped key was restored: %s", got)
	}
}

// End to end on a duplex socket: two live requests with different client keys
// share one operator rule key; a credential rejection arrives before its owner
// is known and must carry neither client's key.
func TestCodexDuplexUnassignedRejectionWithSharedRuleKey(t *testing.T) {
	done := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
		write := func(p string) {
			if e := c.WriteMessage(websocket.TextMessage, []byte(p)); e != nil {
				t.Error(e)
			}
		}
		_, first, err := c.ReadMessage()
		if err != nil {
			t.Error(err)
			return
		}
		received := gjson.GetBytes(first, "prompt_cache_key").String()
		write(`{"type":"response.created","response":{"id":"started","model":"gpt-5.5","output":[]}}`)
		write(`{"type":"response.completed","response":{"id":"started","model":"gpt-5.5","output":[]}}`)
		_, second, err := c.ReadMessage()
		if err != nil {
			t.Error(err)
			return
		}
		if got := gjson.GetBytes(second, "prompt_cache_key").String(); got != received || got != identityTestOperatorKey {
			t.Errorf("second create key = %q, first = %q; want the shared operator key", got, received)
		}
		write(fmt.Sprintf(`{"type":"error","status":401,"error":{"type":"authentication_error","status":401,"message":"credential rejected for prompt_cache_key %s"}}`, received))
		_, _, _ = c.ReadMessage()
	}))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input := make(chan cliproxyexecutor.WebsocketInput, 1)
	ctx = cliproxyexecutor.WithWebsocketInput(cliproxyexecutor.WithDownstreamWebsocket(ctx), input)
	cfg := identityTestConfig(true)
	cfg.Payload = config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}},
		Params: map[string]any{"prompt_cache_key": identityTestOperatorKey},
	}}}
	cfg.Codex.ResponseSteering = true
	cfg.CodexResponseSteering = true
	executor := NewCodexWebsocketsExecutor(cfg)
	executor.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	manager := auth.NewManager(nil, &auth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(executor)
	model := "gpt-5.5"
	candidate := &auth.Auth{ID: identityTestAuthID, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "test", "base_url": upstream.URL, "websockets": "true"}}
	registry.GetGlobalRegistry().RegisterClient(candidate.ID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(candidate.ID) })
	if _, err := manager.Register(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	payloadA := []byte(strings.Replace(string(identityTestPayload()), identityTestCacheKey, finalRoundClientAKey, 1))
	req := cliproxyexecutor.Request{Model: model, Payload: payloadA}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex"), Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()}}
	result, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	var rejection []byte
	var terminal error
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			terminal = chunk.Err
			continue
		}
		switch gjson.GetBytes(chunk.Payload, "type").String() {
		case "response.completed":
			input <- cliproxyexecutor.WebsocketInput{Payload: []byte(`{"type":"response.create","model":"gpt-5.5","prompt_cache_key":"` + finalRoundClientBKey + `","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"second"}]}]}`)}
		case "error":
			rejection = chunk.Payload
		}
	}
	if rejection == nil || terminal == nil {
		t.Fatalf("rejection payload=%q terminal=%v", rejection, terminal)
	}
	for what, text := range map[string]string{"forwarded rejection": string(rejection), "terminal error": terminal.Error()} {
		if strings.Contains(text, finalRoundClientAKey) || strings.Contains(text, finalRoundClientBKey) {
			t.Fatalf("%s carries a client's own key though its owner is unknown: %s", what, text)
		}
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("socket cleanup stalled")
	}
}

func identityKeyFilterConfig(enabled bool) *config.Config {
	cfg := identityTestConfig(enabled)
	cfg.Payload = config.PayloadConfig{Filter: []config.PayloadFilterRule{{
		Models: []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}},
		Params: []string{"prompt_cache_key"},
	}}}
	return cfg
}

func identityKeyClientHeaders(key string) http.Header {
	headers := http.Header{}
	headers.Set("Session-Id", key)
	headers.Set("Conversation_id", key)
	headers.Set("Thread-Id", key)
	headers.Set("X-Client-Request-Id", key)
	headers.Set("X-Codex-Window-Id", key+":0")
	headers.Set("X-Codex-Turn-Metadata", `{"prompt_cache_key":"`+key+`","window_id":"`+key+`:0","turn_id":"turn-1"}`)
	return headers
}

func assertRemovedKeyHeaders(t *testing.T, enabled bool, body []byte, headers http.Header) {
	t.Helper()
	if key := gjson.GetBytes(body, "prompt_cache_key"); key.Exists() {
		t.Fatalf("upstream body still has prompt_cache_key %q", key.String())
	}
	for _, name := range []string{"Session-Id", "Session_id", "Conversation_id"} {
		if got := headerValueCaseInsensitive(headers, name); got != "" {
			t.Fatalf("upstream %s = %q with no key in the body (headers %v)", name, got, headers)
		}
	}
	keys := []string{identityTestCacheKey}
	if enabled {
		keys = append(keys, codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey))
	}
	for _, key := range keys {
		if headersContain(headers, key) {
			t.Fatalf("upstream headers still carry the removed key %q: %v", key, headers)
		}
	}
}

// A payload rule that removes prompt_cache_key also removes the session
// headers and every header copy of the removed key.
func TestCodexPayloadRuleRemovedKeyClearsHeaders(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("http/enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityHTTPServer(t, capture)
			exec := NewCodexExecutor(identityKeyFilterConfig(enabled))
			if _, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: identityKeyClientHeaders(identityTestCacheKey)}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertRemovedKeyHeaders(t, enabled, body, headers)
		})
		t.Run(fmt.Sprintf("websocket/enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityWebsocketServer(t, capture)
			exec := NewCodexWebsocketsExecutor(identityKeyFilterConfig(enabled))
			if _, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Headers: identityKeyClientHeaders(identityTestCacheKey)}); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertRemovedKeyHeaders(t, enabled, body, headers)
		})
	}
}
