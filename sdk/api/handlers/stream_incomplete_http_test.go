package handlers_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/tidwall/gjson"
)

// Recorded catch: Paul's 10-22 mid-stream EOF incident. These requests cross
// the real HTTP upstream -> executor -> auth manager -> client SSE boundary.
func TestIncompleteStreamHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, route := range []struct{ provider, client string }{
		{"compat", "chat"}, {"codex", "responses"}, {"claude", "messages"},
		{"compat", "responses"}, {"compat", "messages"}, {"claude", "chat"}, {"claude", "responses"},
	} {
		for _, mode := range []string{"truncated", "read_error", "upstream_error", "complete", "cancel", "nonstream_error"} {
			if mode == "upstream_error" && route.provider != "compat" {
				continue
			}
			t.Run(route.provider+"/"+route.client+"/"+mode, func(t *testing.T) {
				model := "stream-incomplete-fixture"
				if route.provider == "codex" {
					model = "gpt-6-astra"
				}
				if route.provider == "claude" {
					model = "claude-opus-5-5"
				}
				first, second, terminal := incompleteStreamFixture(route.provider, model)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "nonstream_error" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusBadGateway)
						fmt.Fprint(w, `{"error":{"code":"fixture_failed","message":"fixture HTTP failure"}}`)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					if mode == "read_error" {
						w.Header().Set("Content-Length", "100000")
					}
					w.WriteHeader(http.StatusCreated)
					fmt.Fprint(w, first)
					w.(http.Flusher).Flush()
					fmt.Fprint(w, second)
					w.(http.Flusher).Flush()
					if mode == "cancel" {
						fmt.Fprint(w, ": keep-alive\n\n")
						w.(http.Flusher).Flush()
						<-r.Context().Done()
						return
					}
					if mode == "upstream_error" {
						fmt.Fprint(w, `data: {"error":{"code":"fixture_busy","message":"fixture stream failure"}}`+"\n\n")
					}
					if mode == "complete" {
						fmt.Fprint(w, terminal)
					}
				}))
				defer upstream.Close()
				cfg := &config.Config{}
				manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
				manager.SetRetryConfig(0, 0, 0)
				var exec coreauth.ProviderExecutor
				switch route.provider {
				case "compat":
					exec = runtimeexecutor.NewOpenAICompatExecutor("compat", cfg)
				case "codex":
					exec = runtimeexecutor.NewCodexExecutor(cfg)
				case "claude":
					exec = runtimeexecutor.NewClaudeExecutor(cfg)
				}
				manager.RegisterExecutor(exec)
				id := t.Name()
				if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: route.provider, Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": "synthetic", "base_url": upstream.URL}}); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, route.provider, []*registry.ModelInfo{{ID: model}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
				base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
				router := gin.New()
				var path, payload string
				stream := mode != "nonstream_error"
				switch route.client {
				case "chat":
					path = "/v1/chat/completions"
					payload = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"stream":%t}`, model, stream)
					router.POST(path, openai.NewOpenAIAPIHandler(base).ChatCompletions)
				case "responses":
					path = "/v1/responses"
					payload = fmt.Sprintf(`{"model":%q,"input":"proof","stream":%t}`, model, stream)
					router.POST(path, openai.NewOpenAIResponsesAPIHandler(base).Responses)
				case "messages":
					path = "/v1/messages"
					payload = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"max_tokens":100,"stream":%t}`, model, stream)
					router.POST(path, claude.NewClaudeCodeAPIHandler(base).ClaudeMessages)
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				writer := &incompleteStreamWriter{ResponseRecorder: httptest.NewRecorder()}
				if mode == "cancel" {
					writer.onPartial = cancel
				}
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload)).WithContext(ctx)
				request.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(writer, request)
				body := writer.Body.String()
				t.Logf("client response: %s", body)
				if mode == "nonstream_error" {
					if writer.Code < 400 || strings.Contains(writer.Header().Get("Content-Type"), "event-stream") || !strings.Contains(body, "fixture HTTP failure") {
						t.Fatalf("expected unchanged HTTP error, status=%d body=%s", writer.Code, body)
					}
					return
				}
				if mode == "complete" || mode == "cancel" {
					if strings.Contains(body, "upstream_stream_incomplete") || strings.Contains(body, `"type":"error"`) {
						t.Fatalf("unexpected error: %s", body)
					}
					if mode == "complete" {
						want := map[string]string{"chat": "[DONE]", "responses": "response.completed", "messages": "message_stop"}[route.client]
						if !strings.Contains(body, want) {
							t.Fatalf("missing normal terminal %s: %s", want, body)
						}
					} else if ctx.Err() == nil {
						t.Fatal("cancel did not reach client streaming write")
					}
					return
				}
				var detail gjson.Result
				for _, line := range strings.Split(body, "\n") {
					if !strings.HasPrefix(line, "data:") {
						continue
					}
					candidate := gjson.Parse(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
					if candidate.Get("error").Exists() {
						detail = candidate.Get("error")
					}
				}
				if !detail.Exists() {
					t.Fatalf("missing client error event: %s", body)
				}
				if mode == "upstream_error" && !strings.Contains(detail.Get("message").String(), "fixture_busy") {
					t.Fatalf("lost upstream code/body: %s", body)
				}
				if mode == "read_error" && !strings.Contains(detail.Get("message").String(), "unexpected EOF") {
					t.Fatalf("lost upstream read error: %s", body)
				}
				if route.client == "messages" {
					if !strings.Contains(body, "event: error\n") || detail.Get("type").String() != "api_error" {
						t.Fatalf("bad Anthropic event: %s", body)
					}
					message := detail.Get("message").String()
					for _, field := range []string{"upstream_status=201", "partial_chunks=", "partial_bytes=", "provider=" + route.provider, "model=" + model} {
						if !strings.Contains(message, field) {
							t.Errorf("missing %s: %s", field, message)
						}
					}
				} else {
					if detail.Get("type").String() != "upstream_stream_incomplete" || detail.Get("code").String() != "upstream_stream_incomplete" || detail.Get("upstream_status").Int() != 201 || detail.Get("partial_chunks").Int() < 2 || detail.Get("partial_bytes").Int() <= 0 || detail.Get("provider").String() != route.provider || detail.Get("model").String() != model {
						t.Fatalf("missing diagnostics: %s", body)
					}
				}
				if strings.Contains(body, "data: [DONE]") || strings.Contains(body, `"type":"response.completed"`) && route.client == "responses" {
					t.Fatalf("fabricated success terminal: %s", body)
				}
			})
		}
	}
}

type incompleteStreamWriter struct {
	*httptest.ResponseRecorder
	onPartial func()
}

func (w *incompleteStreamWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(p)
	if w.onPartial != nil && strings.Contains(string(p), "data:") {
		w.onPartial()
	}
	return n, err
}

func (w *incompleteStreamWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func incompleteStreamFixture(provider, model string) (string, string, string) {
	frame := func(payload string) string { return "data: " + payload + "\n\n" }
	switch provider {
	case "compat":
		return frame(fmt.Sprintf(`{"id":"chat-proof","model":%q,"choices":[{"index":0,"delta":{"role":"assistant","content":"partial-one"},"finish_reason":null}]}`, model)),
			frame(`{"id":"chat-proof","choices":[{"index":0,"delta":{"content":"partial-two"},"finish_reason":null}]}`),
			frame(`{"id":"chat-proof","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`) + frame("[DONE]")
	case "codex":
		return frame(fmt.Sprintf(`{"type":"response.created","response":{"id":"resp-proof","model":%q}}`, model)),
			frame(`{"type":"response.output_text.delta","item_id":"msg-proof","output_index":0,"content_index":0,"delta":"partial-two"}`),
			frame(fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp-proof","model":%q,"status":"completed","output":[]}}`, model))
	default:
		return frame(fmt.Sprintf(`{"type":"message_start","message":{"id":"msg-proof","model":%q,"role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`, model)),
			frame(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) + frame(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial-two"}}`),
			frame(`{"type":"content_block_stop","index":0}`) + frame(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`) + frame(`{"type":"message_stop"}`)
	}
}
