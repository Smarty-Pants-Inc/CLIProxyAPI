package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// CLIProxyAPI#111 security pass: error bodies and rejection payloads that echo
// the credential-scoped identifiers must be restored to the client's own
// identifiers, exactly like success payloads.

func assertClientErrorIdentity(t *testing.T, what, text string) {
	t.Helper()
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	if strings.Contains(text, confused) {
		t.Fatalf("%s leaks the credential-scoped key %q: %s", what, confused, text)
	}
	if !strings.Contains(text, identityTestCacheKey) {
		t.Fatalf("%s does not carry the client's prompt_cache_key %q: %s", what, identityTestCacheKey, text)
	}
}

func newIdentityErrorServer(t *testing.T, terminalEvent bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received := gjson.GetBytes(body, "prompt_cache_key").String()
		if terminalEvent {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "data: %s\n\n", `{"type":"response.failed","response":{"id":"resp-err","status":"failed","error":{"code":"server_error","message":"failed for prompt_cache_key `+received+`"}}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":{"type":"invalid_request_error","message":"rejected prompt_cache_key %s"}}`, received)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestCodexIdentityConfuseHTTPErrorBodiesRestoreClientIdentifiers(t *testing.T) {
	for _, terminalEvent := range []bool{false, true} {
		t.Run(fmt.Sprintf("execute/terminal=%t", terminalEvent), func(t *testing.T) {
			server := newIdentityErrorServer(t, terminalEvent)
			exec := NewCodexExecutor(identityTestConfig(true))
			_, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if err == nil {
				t.Fatal("Execute: expected an upstream error")
			}
			assertClientErrorIdentity(t, "Execute error", err.Error())
		})
	}
	t.Run("stream/status", func(t *testing.T) {
		server := newIdentityErrorServer(t, false)
		exec := NewCodexExecutor(identityTestConfig(true))
		result, err := exec.ExecuteStream(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
			Model:   "gpt-5.5",
			Payload: identityTestPayload(),
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Stream: true})
		if err == nil {
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					err = chunk.Err
				}
			}
		}
		if err == nil {
			t.Fatal("ExecuteStream: expected an upstream error")
		}
		assertClientErrorIdentity(t, "ExecuteStream error", err.Error())
	})
}

// A credential rejection on a running duplex socket is forwarded before its
// owning request is resolved; the forwarded payload and the terminal error
// must both carry the client's identifiers.
func TestCodexDuplexCredentialRejectionRestoresClientIdentifiers(t *testing.T) {
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
		_, create, err := c.ReadMessage()
		if err != nil {
			t.Error(err)
			return
		}
		received := gjson.GetBytes(create, "prompt_cache_key").String()
		write := func(p string) {
			if e := c.WriteMessage(websocket.TextMessage, []byte(p)); e != nil {
				t.Error(e)
			}
		}
		write(`{"type":"response.created","response":{"id":"started","model":"gpt-5.5","output":[]}}`)
		write(`{"type":"response.completed","response":{"id":"started","model":"gpt-5.5","output":[]}}`)
		write(fmt.Sprintf(`{"type":"error","status":401,"error":{"type":"authentication_error","status":401,"message":"credential rejected for prompt_cache_key %s"}}`, received))
		_, _, _ = c.ReadMessage()
	}))
	defer upstream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	input := make(chan cliproxyexecutor.WebsocketInput, 1)
	ctx = cliproxyexecutor.WithWebsocketInput(cliproxyexecutor.WithDownstreamWebsocket(ctx), input)
	cfg := identityTestConfig(true)
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
	req := cliproxyexecutor.Request{Model: model, Payload: identityTestPayload()}
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
		if gjson.GetBytes(chunk.Payload, "type").String() == "error" {
			rejection = chunk.Payload
		}
	}
	if rejection == nil || terminal == nil {
		t.Fatalf("rejection payload=%q terminal=%v", rejection, terminal)
	}
	assertClientErrorIdentity(t, "forwarded rejection payload", string(rejection))
	assertClientErrorIdentity(t, "terminal rejection error", terminal.Error())
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("socket cleanup stalled")
	}
}
