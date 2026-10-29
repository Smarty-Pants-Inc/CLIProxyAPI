package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

// Recorded catch: PR #174 review/astra P1. Exercise headers-only and held
// handshake EOF through the real upstream -> executor -> manager -> client path.
func TestBootstrapIncompleteStreamHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, transport := range []string{"compat", "claude", "codex", "codex-ws"} {
		for _, client := range []string{"chat", "responses", "messages"} {
			for _, mode := range []string{"empty", "nonterminal", "preidentity", "partial-line", "empty_read_error", "read_error", "complete"} {
				if mode == "partial-line" && transport != "claude" {
					continue
				}
				t.Run(transport+"/"+client+"/"+mode, func(t *testing.T) {
					hook.Reset()
					provider, model := transport, "bootstrap-fixture"
					if strings.HasPrefix(transport, "codex") {
						provider, model = "codex", "gpt-6-astra"
					}
					if provider == "claude" {
						model = "claude-opus-5-5"
					}
					first, _, terminal := incompleteStreamFixture(provider, model)
					if provider == "compat" {
						first = fmt.Sprintf("data: {\"id\":\"chat-proof\",\"model\":%q,\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n", model)
					}
					wire := first
					switch mode {
					case "empty", "empty_read_error":
						wire = ""
					case "preidentity":
						wire = ": keepalive\n\n"
						if provider == "claude" {
							wire = "data: {\"type\":\"ping\"}\n\n"
						} else if provider == "codex" {
							wire = "data: {\"type\":\"keepalive\"}\n\n"
						}
					case "partial-line":
						wire = `data: {"type":"message_st`
					case "complete":
						// Responses translation requires a message item as well as [DONE].
						if provider == "compat" {
							wire, _, _ = incompleteStreamFixture(provider, model)
						}
						wire += terminal
					}
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if transport == "codex-ws" {
							conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
							if err != nil {
								t.Error(err)
								return
							}
							defer func() {
								if errClose := conn.Close(); errClose != nil {
									t.Logf("close upstream websocket: %v", errClose)
								}
							}()
							if _, _, errRead := conn.ReadMessage(); errRead != nil {
								t.Error(errRead)
								return
							}
							for _, line := range strings.Split(wire, "\n") {
								if strings.HasPrefix(line, "data: ") {
									if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(strings.TrimPrefix(line, "data: "))); errWrite != nil {
										t.Error(errWrite)
									}
								}
							}
							return
						}
						w.Header().Set("Content-Type", "text/event-stream")
						if strings.Contains(mode, "read_error") {
							w.Header().Set("Content-Length", "100000")
						}
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
						fmt.Fprint(w, wire)
					}))
					defer upstream.Close()
					cfg := &config.Config{}
					manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
					manager.SetRetryConfig(0, 0, 0)
					var exec coreauth.ProviderExecutor
					switch transport {
					case "compat":
						exec = runtimeexecutor.NewOpenAICompatExecutor(provider, cfg)
					case "claude":
						exec = runtimeexecutor.NewClaudeExecutor(cfg)
					case "codex":
						exec = runtimeexecutor.NewCodexExecutor(cfg)
					case "codex-ws":
						wsExec := runtimeexecutor.NewCodexWebsocketsExecutor(cfg)
						defer wsExec.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
						exec = wsExec
					}
					manager.RegisterExecutor(exec)
					id := t.Name()
					if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": "synthetic", "base_url": upstream.URL}}); err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
					defer registry.GetGlobalRegistry().UnregisterClient(id)
					base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
					router := gin.New()
					var path, payload string
					switch client {
					case "chat":
						path = "/v1/chat/completions"
						payload = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"stream":true}`, model)
						router.POST(path, openai.NewOpenAIAPIHandler(base).ChatCompletions)
					case "responses":
						path = "/v1/responses"
						payload = fmt.Sprintf(`{"model":%q,"input":"proof","stream":true}`, model)
						router.POST(path, openai.NewOpenAIResponsesAPIHandler(base).Responses)
					case "messages":
						path = "/v1/messages"
						payload = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"max_tokens":100,"stream":true}`, model)
						router.POST(path, claude.NewClaudeCodeAPIHandler(base).ClaudeMessages)
					}
					writer := httptest.NewRecorder()
					request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
					request.Header.Set("Content-Type", "application/json")
					router.ServeHTTP(writer, request)
					body := writer.Body.String()
					if mode == "complete" {
						want := map[string]string{"chat": "[DONE]", "responses": "response.completed", "messages": "message_stop"}[client]
						if writer.Code != http.StatusOK || !strings.Contains(body, want) || strings.Contains(body, "upstream_stream_incomplete") {
							t.Fatalf("terminal not clean: status=%d body=%s", writer.Code, body)
						}
						return
					}
					var detail gjson.Result
					if client == "responses" {
						detail = requireResponsesFailureSSE(t, writer.Code, body)
					} else if writer.Code >= 400 {
						detail = gjson.Get(body, "error")
						wantStatus := http.StatusBadGateway

						if writer.Code != wantStatus {
							t.Errorf("status=%d, want %d", writer.Code, wantStatus)
						}
					} else {
						for _, line := range strings.Split(body, "\n") {
							if strings.HasPrefix(line, "data:") {
								data := gjson.Parse(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
								if data.Get("error").Exists() {
									detail = data.Get("error")
								}
							}
						}
					}
					if detail.Get("code").String() != "upstream_stream_incomplete" || !detail.Get("retryable").Bool() {
						t.Fatalf("missing client incomplete error: status=%d body=%s", writer.Code, body)
					}
					wantType := "upstream_stream_incomplete"
					if client == "messages" {
						wantType = "api_error"
					}
					if detail.Get("type").String() != wantType {
						t.Fatalf("wrong client error type: %s", body)
					}
					if strings.Contains(mode, "read_error") && !strings.Contains(body, "unexpected EOF") {
						t.Fatalf("lost upstream read failure: %s", body)
					}
					if strings.Contains(body, "data: [DONE]") || strings.Contains(body, `"type":"response.completed"`) || strings.Contains(body, `"type":"message_stop"`) {
						t.Fatalf("fabricated terminal: %s", body)
					}
					foundWarn := false
					for _, entry := range hook.AllEntries() {
						if entry.Level == log.WarnLevel && entry.Message == "upstream stream incomplete" && entry.Data["provider"] == provider {
							foundWarn = true
							wantStatus := http.StatusOK
							if transport == "codex-ws" {
								wantStatus = http.StatusSwitchingProtocols
							}
							if provider == "codex" && (entry.Data["partial_bytes"] != int64(0) || entry.Data["partial_chunks"] != int64(0)) {
								t.Errorf("held bootstrap counted as client output: %v", entry.Data)
							}
							if entry.Data["upstream_status"] != wantStatus || entry.Data["code"] != "upstream_stream_incomplete" {
								t.Errorf("wrong warning diagnostics: %v", entry.Data)
							}
						}
					}
					if !foundWarn {
						t.Fatal("missing sanitized incomplete-stream warning")
					}
				})
			}
		}
	}
}

func requireResponsesFailureSSE(t *testing.T, status int, body string) gjson.Result {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("Responses failure status=%d, want %d: %s", status, http.StatusOK, body)
	}

	failureCount := 0
	finalEventName := ""
	var failureError gjson.Result
	for _, event := range strings.Split(strings.TrimSpace(body), "\n\n") {
		event = strings.TrimSpace(event)
		if event == "" {
			continue
		}
		eventName := ""
		var eventData gjson.Result
		for _, line := range strings.Split(event, "\n") {
			if strings.HasPrefix(line, "event: ") {
				eventName = strings.TrimPrefix(line, "event: ")
			}
			if strings.HasPrefix(line, "data: ") {
				eventData = gjson.Parse(strings.TrimPrefix(line, "data: "))
			}
		}
		finalEventName = eventName
		if eventName == "response.failed" {
			failureCount++
			if eventData.Get("type").String() == "response.failed" {
				failureError = eventData.Get("response.error")
			}
		}
	}
	if failureCount != 1 || finalEventName != "response.failed" {
		t.Fatalf("want exactly one final response.failed event, got %d: %s", failureCount, body)
	}
	if strings.Contains(body, "event: response.completed") || strings.Contains(body, `"type":"response.completed"`) || strings.Contains(body, "data: [DONE]") {
		t.Fatalf("Responses failure stream contains a success/DONE event: %s", body)
	}
	if !failureError.Exists() || failureError.Get("code").String() != "upstream_stream_incomplete" || !failureError.Get("retryable").Bool() {
		t.Fatalf("missing nested Responses incomplete error: %s", body)
	}
	return failureError
}
