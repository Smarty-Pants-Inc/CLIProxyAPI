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

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Recorded catch: PR #174 CoS B1/N4. Exercise both credentials through the real
// upstream -> executor -> conductor -> HTTP client path, with cooling enabled.
func TestStreamPreOutputCredentialFailoverHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, transport := range []string{"codex", "codex-ws", "claude"} {
		for _, buffering := range []bool{false, true} {
			for _, allCut := range []bool{false, true} {
				for _, cut := range []string{"empty", "read-error", "preidentity", "partial-line", "created"} {
					// Claude's verified message_start produces a client payload; it is
					// deliberately not eligible for the pre-output replay contract.
					if transport == "claude" && cut == "created" {
						continue
					}
					t.Run(fmt.Sprintf("%s/buffered=%t/all-cut=%t/%s", transport, buffering, allCut, cut), func(t *testing.T) {
						provider, model := "codex", "gpt-6-astra"
						if transport == "claude" {
							provider, model = "claude", "claude-opus-5-5"
						}
						first, delta, terminal := incompleteStreamFixture(provider, model)
						var mu sync.Mutex
						var attempts []string
						upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							account := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
							if account == "" {
								account = r.Header.Get("X-Api-Key")
							}
							mu.Lock()
							attempts = append(attempts, account)
							mu.Unlock()
							wire := first + delta + terminal
							isCut := account == "account-a" || allCut
							if isCut {
								switch cut {
								case "empty", "read-error":
									wire = ""
								case "preidentity":
									wire = "data: {\"type\":\"ping\"}\n\n"
									if provider == "codex" {
										wire = "data: {\"type\":\"keepalive\"}\n\n"
									}
								case "partial-line":
									wire = "data: {\"type\":\"message_st"
								case "created":
									wire = first
								}
							}
							if transport == "codex-ws" {
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
								// A WebSocket message is already framed: only send complete
								// records, then cut before the next message can arrive.
								if cut != "partial-line" || !isCut {
									for _, line := range strings.Split(wire, "\n") {
										if strings.HasPrefix(line, "data: ") {
											if err := conn.WriteMessage(websocket.TextMessage, []byte(strings.TrimPrefix(line, "data: "))); err != nil {
												t.Error(err)
												return
											}
										}
									}
								}
								if isCut && cut == "preidentity" {
									_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
								}
								return
							}
							w.Header().Set("Content-Type", "text/event-stream")
							if isCut && cut == "read-error" {
								w.Header().Set("Content-Length", "100000")
							}
							w.WriteHeader(http.StatusOK)
							w.(http.Flusher).Flush()
							fmt.Fprint(w, wire)
						}))
						defer upstream.Close()
						cfg := &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: buffering, StreamBootstrapBufferingSet: true}}
						manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
						manager.SetRetryConfig(0, 0, 2)
						switch transport {
						case "codex":
							manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
						case "codex-ws":
							exec := runtimeexecutor.NewCodexWebsocketsExecutor(cfg)
							defer exec.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
							manager.RegisterExecutor(exec)
						case "claude":
							manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(cfg))
						}
						var ids []string
						for i, account := range []string{"account-a", "account-b"} {
							id := t.Name() + account
							ids = append(ids, id)
							_, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive,
								Attributes: map[string]string{"api_key": account, "base_url": upstream.URL, "priority": fmt.Sprint(100 - i)}})
							if err != nil {
								t.Fatal(err)
							}
							registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
							defer registry.GetGlobalRegistry().UnregisterClient(id)
						}
						base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
						router := gin.New()
						router.POST("/v1/chat/completions", openai.NewOpenAIAPIHandler(base).ChatCompletions)
						writer := httptest.NewRecorder()
						request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"stream":true}`, model)))
						request.Header.Set("Content-Type", "application/json")
						router.ServeHTTP(writer, request)
						body := writer.Body.String()
						mu.Lock()
						gotAttempts := append([]string(nil), attempts...)
						mu.Unlock()
						if !reflect.DeepEqual(gotAttempts, []string{"account-a", "account-b"}) {
							t.Fatalf("attempts=%v, want A then B; status=%d body=%s", gotAttempts, writer.Code, body)
						}
						if allCut {
							if writer.Code != http.StatusBadGateway || gjson.Get(body, "error.code").String() != "upstream_stream_incomplete" || !gjson.Get(body, "error.retryable").Bool() {
								t.Fatalf("exhaustion: status=%d body=%s", writer.Code, body)
							}
						} else if writer.Code != http.StatusOK || !strings.Contains(body, "[DONE]") || strings.Contains(body, "upstream_stream_incomplete") {
							t.Fatalf("failover: status=%d body=%s", writer.Code, body)
						}
						for _, id := range ids {
							auth, ok := manager.GetByID(id)
							if !ok || auth.Unavailable || !auth.NextRetryAfter.IsZero() {
								t.Fatalf("credential cooled: %+v", auth)
							}
							for model, state := range auth.ModelStates {
								if state.Unavailable || !state.NextRetryAfter.IsZero() {
									t.Fatalf("credential %s model %s cooled: %+v", id, model, state)
								}
							}
						}
					})
				}
			}
		}
	}
}
