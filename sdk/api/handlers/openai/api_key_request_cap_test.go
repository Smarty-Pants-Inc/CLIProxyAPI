package openai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAPIKeyPolicyResponsesRequestCapNeverForwardsExcessTurn(t *testing.T) {
	for _, event := range []string{"response.create", "response.append", "response.steer"} {
		t.Run(event, func(t *testing.T) {
			var frames atomic.Int32
			done := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(8 * time.Second))
				if _, _, err = conn.ReadMessage(); err != nil {
					t.Error(err)
					return
				}
				frames.Add(1)
				conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"r1","model":"gpt-6.1-sol"}}`))
				conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"r1","model":"gpt-6.1-sol","output":[]}}`))
				if _, _, err = conn.ReadMessage(); err == nil {
					frames.Add(1)
				}
			}))
			defer upstream.Close()
			cap := int64(1)
			models := []string{"gpt-6.1-sol"}
			digest := sha256.Sum256([]byte("synthetic-codex-request-cap"))
			cfg := &config.Config{}
			cfg.Codex.ResponseSteering = true
			cfg.CodexResponseSteering = true
			cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"codex-dev4@smartypants.ai-pro.json"}, AllowedProviders: []string{"codex"}, AllowedModels: &models, DailyRequestCap: &cap}}
			manager := coreauth.NewManager(nil, nil, nil)
			manager.SetConfig(cfg)
			manager.RegisterExecutor(runtimeexecutor.NewCodexAutoExecutor(cfg))
			id := "request-cap-" + event
			_, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, FileName: "codex-dev4@smartypants.ai-pro.json", Provider: "codex", Status: coreauth.StatusActive, Metadata: map[string]any{"email": "dev4@smartypants.ai"}, Attributes: map[string]string{"api_key": "synthetic-key", "base_url": upstream.URL, "websockets": "true"}})
			if err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
			defer registry.GetGlobalRegistry().UnregisterClient(id)
			h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager))
			router := gin.New()
			router.GET("/v1/responses", func(c *gin.Context) {
				c.Request = c.Request.WithContext(coreauth.WithClientAPIKey(c.Request.Context(), "synthetic-codex-request-cap"))
				c.Next()
			}, h.ResponsesWebsocket)
			server := httptest.NewServer(router)
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/responses", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(8 * time.Second))
			if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","model":"gpt-6.1-sol","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				if _, _, err = conn.ReadMessage(); err != nil {
					t.Fatal("Nth turn rejected", err)
				}
			}
			if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"`+event+`","previous_response_id":"r1","input":[]}`)); err != nil {
				t.Fatal(err)
			}
			_, payload, err := conn.ReadMessage()
			if err != nil || !strings.Contains(string(payload), "429") || !strings.Contains(string(payload), "00:00 UTC") {
				t.Fatalf("cap error not exposed: %s %v", payload, err)
			}
			conn.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream retained after refusal")
			}
			if frames.Load() != 1 {
				t.Fatalf("excess frame forwarded: %d", frames.Load())
			}
		})
	}
	for _, code := range []string{"api_key_daily_request_cap", "api_key_daily_token_cap", "api_key_model_forbidden"} {
		errMsg := &interfaces.ErrorMessage{StatusCode: 429, Error: &coreauth.Error{Code: code, HTTPStatus: 429}}
		if !shouldExposeResponsesUpstreamError(errMsg) || shouldReplayResponsesWebsocketPinnedAuthFailure(errMsg) || shouldReleaseResponsesWebsocketPinnedAuth(errMsg) {
			t.Fatal("client refusal treated as shared credential failure", code)
		}
	}
}
