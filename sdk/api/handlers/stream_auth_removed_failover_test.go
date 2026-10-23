package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Recorded catch: PR #174 round-5 N2. Remove A only after its WS request
// reaches upstream, close its live session, then require the conductor to use B.
func TestStreamCredentialRemovedMidRequestFailover(t *testing.T) {
	for _, provider := range []string{"codex", "xai"} {
		t.Run(provider, func(t *testing.T) {
			cfg := &config.Config{}
			manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
			manager.SetRetryConfig(0, 0, 2)
			var mu sync.Mutex
			var attempts []string
			firstID := t.Name() + "account-a"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				account := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				attempts = append(attempts, account)
				mu.Unlock()
				if account == "account-a" {
					manager.Remove(context.Background(), firstID)
					if provider == "codex" {
						runtimeexecutor.CloseCodexWebsocketSessionsForAuthID(firstID, "auth_removed")
					} else {
						runtimeexecutor.CloseXAIWebsocketSessionsForAuthID(firstID, "auth_removed")
					}
					// Hold the server connection until the client closes it: this is a local
					// credential teardown, not a racing upstream EOF.
					_, _, _ = conn.ReadMessage()
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp-healthy","model":%q,"status":"completed","output":[],"usage":{"input_tokens":0,"output_tokens":0}}}`, map[string]string{"codex": "gpt-6-astra", "xai": "grok-4.3"}[provider]))); err != nil {
					t.Error(err)
				}
			}))
			defer upstream.Close()
			model := "gpt-6-astra"
			if provider == "codex" {
				exec := runtimeexecutor.NewCodexWebsocketsExecutor(cfg)
				manager.RegisterExecutor(exec)
				defer exec.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
			} else {
				model = "grok-4.3"
				exec := runtimeexecutor.NewXAIWebsocketsExecutor(cfg)
				manager.RegisterExecutor(exec)
				defer exec.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
			}
			for i, account := range []string{"account-a", "account-b"} {
				id := t.Name() + account
				_, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": account, "base_url": upstream.URL, "websockets": "true", "priority": fmt.Sprint(100 - i)}})
				if err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
			}
			req := coreexecutor.Request{Model: model, Payload: []byte(fmt.Sprintf(`{"model":%q,"input":"proof"}`, model))}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, Metadata: map[string]any{coreexecutor.ExecutionSessionMetadataKey: t.Name()}}
			ctx := context.Background()
			if provider == "codex" {
				resp, err := manager.Execute(ctx, []string{provider}, req, opts)
				if err != nil || !strings.Contains(string(resp.Payload), "resp-healthy") {
					t.Fatalf("nonstream failed: %v body=%s", err, resp.Payload)
				}
			} else {
				result, err := manager.ExecuteStream(ctx, []string{provider}, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				var body strings.Builder
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
					body.Write(chunk.Payload)
				}
				if !strings.Contains(body.String(), "resp-healthy") {
					t.Fatalf("missing completion: %s", body.String())
				}
			}
			mu.Lock()
			got := append([]string(nil), attempts...)
			mu.Unlock()
			if !reflect.DeepEqual(got, []string{"account-a", "account-b"}) {
				t.Fatalf("attempts=%v", got)
			}
			if _, exists := manager.GetByID(firstID); exists {
				t.Fatal("removed credential was restored")
			}
		})
	}
}
