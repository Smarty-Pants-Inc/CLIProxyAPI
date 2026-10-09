package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// End-to-end coverage for credential-scoped identity remapping on the merged
// HTTP, HTTP streaming and WebSocket Codex paths (CLIProxyAPI#111 review).

const (
	identityTestAuthID       = "auth-identity-1"
	identityTestCacheKey     = "client-cache-key-1"
	identityTestInstallation = "client-install-1"
)

func identityTestPayload() []byte {
	return []byte(`{"model":"gpt-5.5","prompt_cache_key":"` + identityTestCacheKey + `","client_metadata":{"x-codex-installation-id":"` + identityTestInstallation + `"},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
}

func identityTestConfig(enabled bool) *config.Config {
	cfg := &config.Config{
		Routing: config.RoutingConfig{SessionAffinity: true},
		Codex:   config.CodexConfig{IdentityConfuse: enabled},
	}
	cfg.DisableImageGeneration = config.DisableImageGenerationAll
	return cfg
}

func identityTestAuth(baseURL string) *cliproxyauth.Auth {
	auth := codexOAuthTestAuth(baseURL)
	auth.ID = identityTestAuthID
	return auth
}

// identityTestCompleted echoes the identifiers the upstream received, the way
// the Responses API echoes prompt_cache_key, so the restore step is observable.
func identityTestCompleted(receivedKey string) string {
	return `{"type":"response.completed","response":{"id":"resp-identity","object":"response","status":"completed","model":"gpt-5.5","prompt_cache_key":"` + receivedKey + `","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"key=` + receivedKey + `"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
}

type identityTestCapture struct {
	mu      sync.Mutex
	body    []byte
	headers http.Header
}

func (c *identityTestCapture) snapshot() ([]byte, http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body, c.headers
}

func newIdentityHTTPServer(t *testing.T, capture *identityTestCapture) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("read upstream body: %v", errRead)
		}
		capture.mu.Lock()
		capture.body = body
		capture.headers = r.Header.Clone()
		capture.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", identityTestCompleted(gjson.GetBytes(body, "prompt_cache_key").String()))
	}))
	t.Cleanup(server.Close)
	return server
}

func newIdentityWebsocketServer(t *testing.T, capture *identityTestCapture) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handshake := r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			_, payload, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			capture.mu.Lock()
			capture.body = payload
			capture.headers = handshake
			capture.mu.Unlock()
			completed := identityTestCompleted(gjson.GetBytes(payload, "prompt_cache_key").String())
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(completed)); errWrite != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func headersContain(headers http.Header, value string) bool {
	for _, values := range headers {
		for _, v := range values {
			if strings.Contains(v, value) {
				return true
			}
		}
	}
	return false
}

// assertIdentityRequest checks the upstream request: remapped per credential
// when enabled, untouched when disabled.
func assertIdentityRequest(t *testing.T, enabled bool, body []byte, headers http.Header) {
	t.Helper()
	wantKey := identityTestCacheKey
	wantInstall := identityTestInstallation
	if enabled {
		wantKey = codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
		wantInstall = codexIdentityConfuseUUID(identityTestAuthID, "installation", identityTestInstallation)
	}
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != wantKey {
		t.Fatalf("upstream prompt_cache_key = %q, want %q (enabled=%t)", got, wantKey, enabled)
	}
	if got := gjson.GetBytes(body, "client_metadata.x-codex-installation-id").String(); got != wantInstall {
		t.Fatalf("upstream installation id = %q, want %q (enabled=%t)", got, wantInstall, enabled)
	}
	if enabled {
		if strings.Contains(string(body), identityTestCacheKey) || strings.Contains(string(body), identityTestInstallation) {
			t.Fatalf("upstream body leaks a client identifier: %s", body)
		}
		if headersContain(headers, identityTestCacheKey) {
			t.Fatalf("upstream headers leak the client prompt_cache_key: %v", headers)
		}
		if !headersContain(headers, wantKey) {
			t.Fatalf("upstream headers do not carry the remapped session key %q: %v", wantKey, headers)
		}
	}
}

// assertIdentityResponse checks that the client sees its own identifiers.
func assertIdentityResponse(t *testing.T, enabled bool, clientOutput string) {
	t.Helper()
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	if !strings.Contains(clientOutput, "key="+identityTestCacheKey) {
		t.Fatalf("client output does not carry the original prompt_cache_key (enabled=%t): %s", enabled, clientOutput)
	}
	if strings.Contains(clientOutput, confused) {
		t.Fatalf("client output leaks the credential-scoped key: %s", clientOutput)
	}
}

func TestCodexIdentityConfuseHTTPExecute(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityHTTPServer(t, capture)
			exec := NewCodexExecutor(identityTestConfig(enabled))
			resp, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertIdentityRequest(t, enabled, body, headers)
			assertIdentityResponse(t, enabled, string(resp.Payload))
		})
	}
}

func TestCodexIdentityConfuseHTTPExecuteStream(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityHTTPServer(t, capture)
			exec := NewCodexExecutor(identityTestConfig(enabled))
			result, err := exec.ExecuteStream(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Stream: true})
			if err != nil {
				t.Fatalf("ExecuteStream: %v", err)
			}
			var out strings.Builder
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatalf("stream chunk error: %v", chunk.Err)
				}
				out.Write(chunk.Payload)
			}
			body, headers := capture.snapshot()
			assertIdentityRequest(t, enabled, body, headers)
			assertIdentityResponse(t, enabled, out.String())
		})
	}
}

func TestCodexIdentityConfuseWebsocketExecute(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityWebsocketServer(t, capture)
			exec := NewCodexWebsocketsExecutor(identityTestConfig(enabled))
			resp, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertIdentityRequest(t, enabled, body, headers)
			assertIdentityResponse(t, enabled, string(resp.Payload))
		})
	}
}

func TestCodexIdentityConfuseWebsocketExecuteStream(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityWebsocketServer(t, capture)
			exec := NewCodexWebsocketsExecutor(identityTestConfig(enabled))
			result, err := exec.ExecuteStream(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Stream: true})
			if err != nil {
				t.Fatalf("ExecuteStream: %v", err)
			}
			var out strings.Builder
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Fatalf("stream chunk error: %v", chunk.Err)
				}
				out.Write(chunk.Payload)
			}
			body, headers := capture.snapshot()
			assertIdentityRequest(t, enabled, body, headers)
			assertIdentityResponse(t, enabled, out.String())
		})
	}
}

// Payload rules stay the final barrier: an operator override of
// prompt_cache_key wins over the built-in credential-scoped remap.
func TestCodexIdentityConfusePayloadRuleStillWins(t *testing.T) {
	cfg := identityTestConfig(true)
	cfg.Payload = config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}},
		Params: map[string]any{"prompt_cache_key": "operator-key"},
	}}}
	capture := &identityTestCapture{}
	server := newIdentityHTTPServer(t, capture)
	exec := NewCodexExecutor(cfg)
	if _, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: identityTestPayload(),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	body, _ := capture.snapshot()
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != "operator-key" {
		t.Fatalf("upstream prompt_cache_key = %q, want operator-key", got)
	}
}
