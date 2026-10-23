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

func reviewFixture(provider, model string) (string, string) {
	frame := func(s string) string {
		event := ""
		if provider == "claude" {
			event = "event: " + gjson.Get(s, "type").String() + "\n"
		}
		return event + "data: " + s + "\n\n"
	}
	switch provider {
	case "compat":
		return frame(fmt.Sprintf(`{"id":"chat-proof","model":%q,"choices":[{"index":0,"delta":{"role":"assistant","content":"partial-two"},"finish_reason":null}]}`, model)), frame(`{"id":"chat-proof","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`) + frame("[DONE]")
	case "codex":
		return frame(fmt.Sprintf(`{"type":"response.created","response":{"id":"resp-proof","model":%q}}`, model)) + frame(`{"type":"response.output_text.delta","item_id":"msg-proof","output_index":0,"content_index":0,"delta":"partial-two"}`), frame(fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp-proof","model":%q,"status":"completed","output":[]}}`, model))
	default:
		return frame(fmt.Sprintf(`{"type":"message_start","message":{"id":"msg-proof","model":%q,"role":"assistant","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`, model)) + frame(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) + frame(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"partial-two"}}`), frame(`{"type":"content_block_stop","index":0}`) + frame(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`) + frame(`{"type":"message_stop"}`)
	}
}

func reviewRequest(t *testing.T, provider, client string, change func(string, string) string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	model := "stream-review-fixture"
	if provider == "codex" {
		model = "gpt-6-astra"
	}
	if provider == "claude" {
		model = "claude-opus-5-5"
	}
	first, terminal := reviewFixture(provider, model)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// One upstream write followed by EOF also covers buffered terminal+EOF.
		fmt.Fprint(w, change(first, terminal))
	}))
	defer upstream.Close()
	cfg := &config.Config{}
	manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	var exec coreauth.ProviderExecutor
	switch provider {
	case "compat":
		exec = runtimeexecutor.NewOpenAICompatExecutor("compat", cfg)
	case "codex":
		exec = runtimeexecutor.NewCodexExecutor(cfg)
	case "claude":
		exec = runtimeexecutor.NewClaudeExecutor(cfg)
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
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, "partial-two") {
		t.Fatalf("lost stream: HTTP%d %s", recorder.Code, body)
	}
	return body
}

// Recorded catches: PR #174's independent review found a cross-client privacy
// leak and a false incomplete-stream failure after a multiline Claude terminal.
// Keep these real-router tests at the upstream/client trust boundary.
func TestReviewPrivateURLAndAccountNotForwarded(t *testing.T) {
	for _, provider := range []string{"compat", "codex", "claude"} {
		for _, client := range []string{"chat", "responses", "messages"} {
			t.Run(provider+"/"+client, func(t *testing.T) {
				body := reviewRequest(t, provider, client, func(first, terminal string) string {
					errFrame := "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"code\":\"server_error\",\"message\":\"upstream https://billing.internal.example/v1/accounts/acct_other_482 failed for account acct_other_482\"}}\n\n"
					return first + errFrame
				})
				var detail gjson.Result
				for _, line := range strings.Split(body, "\n") {
					root := gjson.Parse(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
					if candidate := root.Get("error"); candidate.IsObject() {
						detail = candidate
					} else if candidate := root.Get("response.error"); candidate.IsObject() {
						detail = candidate
					}
				}
				if detail.Get("code").String() != "server_error" || detail.Get("type").String() != "server_error" || !detail.Get("retryable").IsBool() || !detail.Get("retryable").Bool() {
					t.Fatalf("lost error classification: %s", body)
				}
				if got := detail.Get("message").String(); got != "upstream server error: server_error" {
					t.Errorf("want fixed classed message, got %q", got)
				}
				for _, private := range []string{"https://", "billing.internal.example", "acct_other_482"} {
					if strings.Contains(body, private) {
						t.Errorf("private upstream diagnostic escaped to client (%s): %s", private, body)
					}
				}
			})
		}
	}
}

func TestReviewClaudeMultilineTerminal(t *testing.T) {
	for _, client := range []string{"chat", "responses", "messages"} {
		t.Run(client, func(t *testing.T) {
			body := reviewRequest(t, "claude", client, func(first, terminal string) string {
				terminal = strings.Replace(terminal, "data: {\"type\":\"message_stop\"}", "data: {\"type\":\ndata: \"message_stop\"}", 1)
				return first + terminal
			})
			if strings.Contains(body, "upstream_stream_incomplete") || strings.Contains(body, "event: error") {
				t.Fatalf("complete, valid multiline message_stop reported as failure: %s", body)
			}
		})
	}
}

func TestReviewNormalTerminalAndEOF(t *testing.T) {
	for _, provider := range []string{"compat", "codex", "claude"} {
		for _, client := range []string{"chat", "responses", "messages"} {
			for _, mode := range []string{"plain", "crlf_comments", "last_line_eof"} {
				t.Run(provider+"/"+client+"/"+mode, func(t *testing.T) {
					body := reviewRequest(t, provider, client, func(first, terminal string) string {
						wire := first + terminal
						switch mode {
						case "crlf_comments":
							wire = strings.ReplaceAll(": heartbeat\n\n"+wire, "\n", "\r\n")
						case "last_line_eof":
							wire = strings.TrimRight(wire, "\n")
						}
						return wire
					})
					if strings.Contains(body, "upstream_stream_incomplete") || strings.Contains(body, "event: error") || strings.Contains(body, "event: response.failed") {
						t.Fatalf("normal stream failed: %s", body)
					}
					expected := map[string]string{"chat": "[DONE]", "responses": "response.completed", "messages": "message_stop"}[client]
					if !strings.Contains(body, expected) {
						t.Fatalf("missing terminal %s: %s", expected, body)
					}
				})
			}
		}
	}
}
