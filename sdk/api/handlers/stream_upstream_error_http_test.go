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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

// Recorded catch: smarty-dev#16084, thinking/tool output followed by a bare
// API error inside HTTP 200. Exercise the real HTTP and translation boundaries.
func TestUpstreamErrorFrameHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, provider := range []string{"compat", "codex", "claude"} {
		for _, client := range []string{"chat", "responses", "codex-responses", "messages"} {
			for _, kind := range []string{"server", "code_only", "flat", "failed", "typeless", "multiline", "invalid", "overloaded", "rate_limit", "status", "cut"} {
				if (kind == "failed" || kind == "flat") && provider != "codex" {
					continue
				}
				t.Run(provider+"/"+client+"/"+kind, func(t *testing.T) {
					hook.Reset()
					model := "stream-frame-fixture"
					if provider == "codex" {
						model = "gpt-6-astra"
					}
					if provider == "claude" {
						model = "claude-opus-5-5"
					}
					code, errType, retryable := "server_error", "server_error", true
					switch kind {
					case "invalid":
						code, errType, retryable = "invalid_value", "invalid_request_error", false
					case "overloaded":
						code, errType = "server_is_overloaded", "overloaded_error"
					case "rate_limit":
						code, errType = "rate_limit_exceeded", "rate_limit_error"
					case "status":
						code, errType = "fixture_down", "api_error"
					}
					message := "fixture upstream failure"
					clientMessage := "upstream server error: " + code
					switch kind {
					case "invalid":
						clientMessage = "upstream request rejected: " + code
					case "overloaded":
						clientMessage = "upstream overloaded: " + code
					case "rate_limit":
						clientMessage = "upstream rate limited: " + code
					}
					detail := fmt.Sprintf(`{"code":%q,"type":%q,"message":%q,"api_key":"nested-secret","extra":{"token":"nested-token"}}`, code, errType, message+" api_key=sk-test-secret-123456789 token=token-secret owner@example.com")
					if kind == "status" {
						detail = strings.TrimSuffix(detail, "}") + `,"status_code":503}`
					}
					if kind == "code_only" {
						detail = `{"code":"server_error","message":"fixture upstream failure"}`
					}
					frame := "data: {\"error\":" + detail + "}\n\n"
					if provider != "compat" {
						frame = "event: error\ndata: {\"type\":\"error\",\"error\":" + detail + "}\n\n"
					}
					switch kind {
					case "flat":
						frame = "event: error\ndata: {\"type\":\"error\",\"code\":\"server_error\",\"error_type\":\"server_error\",\"message\":\"fixture upstream failure\"}\n\n"
					case "failed":
						frame = "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":" + detail + "}}\n\n"
					case "typeless":
						frame = "event: error\ndata: {\"error\":" + detail + "}\n\n"
					case "multiline":
						frame = "event: error\ndata: {\"error\":\ndata: " + detail + "}\n\n"
					case "cut":
						frame = ""
					}
					first, second, _ := incompleteStreamFixture(provider, model)
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "text/event-stream")
						w.WriteHeader(http.StatusOK)
						for _, part := range []string{first, second, frame} {
							fmt.Fprint(w, part)
							w.(http.Flusher).Flush()
						}
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
					if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Label: "fixture-label", Provider: provider, Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": "synthetic", "base_url": upstream.URL}}); err != nil {
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
					case "responses", "codex-responses":
						path = "/v1/responses"
						payload = fmt.Sprintf(`{"model":%q,"input":"proof","stream":true}`, model)
						router.POST(path, openai.NewOpenAIResponsesAPIHandler(base).Responses)
					case "messages":
						path = "/v1/messages"
						payload = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"proof"}],"max_tokens":100,"stream":true}`, model)
						router.POST(path, claude.NewClaudeCodeAPIHandler(base).ClaudeMessages)
					}
					request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
					request.Header.Set("Content-Type", "application/json")
					if client == "codex-responses" {
						request.Header.Set("User-Agent", "codex_cli_rs/0.1.0")
					}
					writer := httptest.NewRecorder()
					router.ServeHTTP(writer, request)
					body := writer.Body.String()
					if writer.Code != http.StatusOK || !strings.Contains(body, "partial-two") {
						t.Fatalf("lost partial stream: HTTP%d %s", writer.Code, body)
					}
					var detailResult gjson.Result
					count := 0
					for _, line := range strings.Split(body, "\n") {
						if !strings.HasPrefix(line, "data:") {
							continue
						}
						root := gjson.Parse(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
						candidate := root.Get("error")
						if !candidate.IsObject() {
							candidate = root.Get("response.error")
						}
						if candidate.IsObject() {
							count++
							detailResult = candidate
						}
					}
					if count != 1 {
						t.Fatalf("want exactly one error, got %d: %s", count, body)
					}
					if strings.Contains(body, "data: [DONE]") || strings.Contains(body, `"type":"response.completed"`) || strings.Contains(body, `"type":"message_stop"`) {
						t.Fatalf("fake success: %s", body)
					}
					if kind == "cut" {
						if !strings.Contains(body, "upstream_stream_incomplete") {
							t.Fatalf("missing explicit incomplete error: %s", body)
						}
						return
					}
					if detailResult.Get("code").String() != code || detailResult.Get("type").String() != errType || detailResult.Get("message").String() != clientMessage || !detailResult.Get("retryable").IsBool() || detailResult.Get("retryable").Bool() != retryable {
						t.Fatalf("lost error classification: %s", body)
					}
					if client == "messages" && !strings.Contains(body, "event: error\n") {
						t.Fatalf("missing Anthropic event: %s", body)
					}
					if (client == "responses" || client == "codex-responses") && !strings.Contains(body, "event: response.failed\n") {
						t.Fatalf("missing Responses failed event: %s", body)
					}
					for _, secret := range []string{"sk-test-secret-123456789", "token-secret", "owner@example.com", "nested-secret", "nested-token"} {
						if strings.Contains(body, secret) {
							t.Errorf("client leaked %q: %s", secret, body)
						}
					}
					warns := 0
					for _, entry := range hook.AllEntries() {
						if entry.Level != log.WarnLevel || entry.Message != "upstream stream error" {
							continue
						}
						warns++
						for key, want := range map[string]string{"provider": provider, "model": model, "auth_label": "fixture-label", "code": code, "type": errType} {
							if entry.Data[key] != want {
								t.Errorf("warn %s=%v, want %q", key, entry.Data[key], want)
							}
						}
						if n, ok := entry.Data["partial_bytes"].(int64); !ok || n <= 0 {
							t.Errorf("missing partial bytes: %v", entry.Data)
						}
					}
					if warns != 1 {
						t.Errorf("want one sanitized upstream warn, got %d", warns)
					}
				})
			}
		}
	}
}
