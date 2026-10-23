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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/gemini"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// Recorded catch: PR #174 CoS B1/N4. Exercise both credentials through the real
// upstream -> executor -> conductor -> HTTP client path, with cooling enabled.
func TestStreamPreOutputCredentialFailoverHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, client := range []string{"chat", "responses", "messages", "gemini"} {
		for _, transport := range []string{"codex", "codex-ws", "claude", "compat"} {
			for _, buffering := range []bool{false, true} {
				for _, allCut := range []bool{false, true} {
					for _, cut := range []string{"empty", "read-error", "preidentity", "partial-line", "created", "after-start-ping", "after-start-text", "tool", "output"} {
						if strings.HasPrefix(cut, "after-start-") && transport != "claude" || cut == "tool" && transport != "claude" && transport != "compat" {
							continue
						}
						// Replay is determined by downstream output and upstream work, not
						// merely by an upstream identity/created event.
						replay := cut != "output" && cut != "tool"
						if cut == "created" || strings.HasPrefix(cut, "after-start-") {
							if transport == "claude" {
								replay = client == "gemini"
							}
							if transport == "compat" {
								replay = false
							}
							if strings.HasPrefix(transport, "codex") {
								replay = buffering || client == "chat"
							}
						}
						t.Run(fmt.Sprintf("%s/%s/buffered=%t/all-cut=%t/%s", transport, client, buffering, allCut, cut), func(t *testing.T) {
							provider, model := "codex", "gpt-6-astra"
							if transport == "claude" {
								provider, model = "claude", "claude-opus-5-5"
							} else if transport == "compat" {
								provider, model = "compat", "stream-failover-fixture"
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
										wire = ": keep-alive\n\n"
										if provider == "claude" {
											wire = "data: {\"type\":\"ping\"}\n\n"
										}
										if provider == "codex" {
											wire = "data: {\"type\":\"keepalive\"}\n\n"
										}
									case "partial-line":
										wire = "data: {\"type\":\"message_st"
									case "created":
										wire = first
									case "after-start-ping":
										wire = first + "data: {\"type\":\"ping\"}\n\n"
									case "after-start-text":
										wire = first + "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
									case "tool":
										wire = first + "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"tool-1\",\"name\":\"web_search\",\"input\":{}}}\n\n"
										if provider == "compat" {
											wire = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tool-1\",\"type\":\"function\",\"function\":{\"name\":\"search\",\"arguments\":\"\"}}]}}]}\n\n"
										}
									case "output":
										wire = first + delta
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
							case "compat":
								manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor("compat", cfg))
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
							path, payload := streamFailoverClientRoute(router, base, client, model)
							writer := httptest.NewRecorder()
							request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
							request.Header.Set("Content-Type", "application/json")
							router.ServeHTTP(writer, request)
							body := writer.Body.String()
							mu.Lock()
							gotAttempts := append([]string(nil), attempts...)
							mu.Unlock()
							wantAttempts := []string{"account-a", "account-b"}
							if !replay {
								wantAttempts = []string{"account-a"}
							}
							t.Logf("MATRIX transport=%s client=%s buffered=%t cut=%s allCut=%t replay=%t attempts=%v status=%d", transport, client, buffering, cut, allCut, replay, gotAttempts, writer.Code)
							if !reflect.DeepEqual(gotAttempts, wantAttempts) {
								t.Fatalf("attempts=%v, want %v; status=%d body=%s", gotAttempts, wantAttempts, writer.Code, body)
							}
							if !replay {
								wantStatus := http.StatusOK
								if cut == "tool" && client == "gemini" {
									wantStatus = http.StatusBadGateway
								}
								if writer.Code != wantStatus || !strings.Contains(body, "upstream_stream_incomplete") {
									t.Fatalf("post-output/work: status=%d body=%s", writer.Code, body)
								}
							} else if allCut {
								if writer.Code != http.StatusBadGateway || gjson.Get(body, "error.code").String() != "upstream_stream_incomplete" || !gjson.Get(body, "error.retryable").Bool() {
									t.Fatalf("exhaustion: status=%d body=%s", writer.Code, body)
								}
							} else if writer.Code != http.StatusOK || !strings.Contains(body, map[string]string{"chat": "[DONE]", "responses": "response.completed", "messages": "message_stop", "gemini": "candidates"}[client]) || strings.Contains(body, "upstream_stream_incomplete") {
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
}

func streamFailoverClientRoute(router *gin.Engine, base *handlers.BaseAPIHandler, client, model string) (string, string) {
	switch client {
	case "responses":
		router.POST("/v1/responses", openai.NewOpenAIResponsesAPIHandler(base).Responses)
		return "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"proof","stream":true}`, model)
	case "messages":
		router.POST("/v1/messages", claude.NewClaudeCodeAPIHandler(base).ClaudeMessages)
		return "/v1/messages", fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"max_tokens":100,"stream":true}`, model)
	case "gemini":
		router.POST("/v1beta/models/*action", gemini.NewGeminiAPIHandler(base).GeminiHandler)
		return "/v1beta/models/" + model + ":streamGenerateContent?alt=sse", `{"contents":[{"role":"user","parts":[{"text":"proof"}]}]}`
	default:
		router.POST("/v1/chat/completions", openai.NewOpenAIAPIHandler(base).ChatCompletions)
		return "/v1/chat/completions", fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"stream":true}`, model)
	}
}
