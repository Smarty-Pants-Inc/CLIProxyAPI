package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/tidwall/gjson"
)

const (
	codexTerminalHTTPModel     = "gpt-5.6-sol"
	codexTerminalHTTPRequestID = "gateway-terminal-fixture-17478"
	codexTerminalHTTPSecret    = "RAW_SECRET_17478_DO_NOT_FORWARD"
	codexTerminalHTTPCreated   = `{"type":"response.created","response":{"id":"resp_terminal_http","model":"gpt-5.6-sol","status":"in_progress"}}`
	codexTerminalHTTPDelta     = `{"type":"response.output_text.delta","item_id":"msg_terminal_http","output_index":0,"content_index":0,"delta":"partial answer"}`
	codexTerminalHTTPCompleted = `{"type":"response.completed","response":{"id":"resp_terminal_http","model":"gpt-5.6-sol","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3},"future":{"preserved":true}}}`
)

// Captured from the HEAD handler through this same real HTTP path on 2026-10-29.
// The existing gateway adds SSE whitespace and usage detail fields. Preserve its
// exact downstream bytes, not an assumed identity with the upstream fixture.
func codexTerminalHTTPCompletedBaseline() string {
	completed := strings.Replace(codexTerminalHTTPCompleted, `"total_tokens":3`, `"total_tokens":3,"output_tokens_details":{"reasoning_tokens":0},"input_tokens_details":{"cached_tokens":0}`, 1)
	return "\n\n" + strings.TrimSuffix(codexTerminalHTTPSSE(codexTerminalHTTPCreated), "\n\n") + "\n\n\n\n" + strings.TrimSuffix(codexTerminalHTTPSSE(codexTerminalHTTPDelta), "\n\n") + "\n\n\n\n" + strings.TrimSuffix(codexTerminalHTTPSSE(completed), "\n\n") + "\n\n\n"
}

func codexTerminalHTTPSSE(events ...string) string {
	var body strings.Builder
	for _, event := range events {
		fmt.Fprintf(&body, "event: %s\ndata: %s\n\n", gjson.Get(event, "type").String(), event)
	}
	return body.String()
}

// Only the upstream body is a fixture: the real Codex scanner, model guard,
// auth manager, and HTTP Responses handler process this read failure.
type codexTerminalHTTPReadTransport struct {
	t          *testing.T
	primaryURL string
	calls      atomic.Int32
}

func (p *codexTerminalHTTPReadTransport) RoundTripperFor(auth *cliproxyauth.Auth) http.RoundTripper {
	if auth.Attributes["base_url"] != p.primaryURL {
		return http.DefaultTransport
	}
	return p
}
func (p *codexTerminalHTTPReadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.calls.Add(1)
	codexTerminalHTTPAssertRequest(p.t, req)
	body := &codexTerminalHTTPReadBody{Reader: strings.NewReader(codexTerminalHTTPSSE(codexTerminalHTTPCreated, codexTerminalHTTPDelta))}
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: body, Request: req}, nil
}

type codexTerminalHTTPReadBody struct{ *strings.Reader }

func (b *codexTerminalHTTPReadBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF {
		return 0, errors.New("upstream read failed: api_key=" + codexTerminalHTTPSecret)
	}
	return n, err
}
func (*codexTerminalHTTPReadBody) Close() error { return nil }

func codexTerminalHTTPAssertRequest(t *testing.T, req *http.Request) {
	t.Helper()
	body, errRead := io.ReadAll(req.Body)
	if errRead != nil {
		t.Errorf("read upstream request: %v", errRead)
		return
	}
	if req.Method != http.MethodPost || req.URL.Path != "/responses" || gjson.GetBytes(body, "model").String() != codexTerminalHTTPModel || !gjson.GetBytes(body, "stream").Bool() {
		t.Errorf("unexpected real Codex upstream request: %s %s %s", req.Method, req.URL.Path, body)
	}
}

func codexTerminalHTTPManager(t *testing.T, buffering bool, urls ...string) *cliproxyauth.Manager {
	t.Helper()
	cfg := &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: buffering, StreamBootstrapBufferingSet: true, DisableCodexCloaking: true}}
	manager := cliproxyauth.NewManager(nil, &cliproxyauth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(NewCodexExecutor(cfg))
	for i, endpoint := range urls {
		id := fmt.Sprintf("terminal-http-%d-%s", i, t.Name())
		auth := &cliproxyauth.Auth{ID: id, Provider: "codex", Status: cliproxyauth.StatusActive, Attributes: map[string]string{"api_key": "fixture-only-token", "base_url": endpoint}}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: codexTerminalHTTPModel}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errRegister := manager.Register(t.Context(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	return manager
}

func codexTerminalHTTPGateway(t *testing.T, manager *cliproxyauth.Manager, userAgent string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.POST("/v1/responses", h.Responses)
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-5.6-sol","input":"hello","stream":true}`))
	request = request.WithContext(logging.WithRequestID(context.Background(), codexTerminalHTTPRequestID))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("X-Request-ID", codexTerminalHTTPSecret)
	// Exercise the same Responses Lite request option accepted from Codex clients.
	request.Header.Set(codexResponsesLiteHeader, "true")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	t.Logf("ACTUAL HTTP %d Content-Type=%s\n--- SSE BEGIN ---\n%s\n--- SSE END ---", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Body.String())
	return recorder
}

func codexTerminalHTTPAssertFailed(t *testing.T, recorder *httptest.ResponseRecorder, partial bool) {
	t.Helper()
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.HasPrefix(recorder.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("failure is not HTTP 200 SSE: %d %s", recorder.Code, body)
	}
	var failed []gjson.Result
	var dataTypes []string
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		value := gjson.Parse(data)
		dataTypes = append(dataTypes, value.Get("type").String())
		if value.Get("type").String() == "response.failed" {
			failed = append(failed, value)
		}
	}
	if strings.Contains(body, codexTerminalHTTPSecret) {
		t.Errorf("terminal leaked synthetic secret/client request ID: %s", body)
	}
	if strings.Count(body, "event: response.failed\n") != 1 || len(failed) != 1 {
		t.Errorf("want ONE response.failed terminal, got %d: %s", len(failed), body)
		return
	}
	if len(dataTypes) == 0 || dataTypes[len(dataTypes)-1] != "response.failed" || strings.Contains(body, "event: response.completed\n") || strings.Contains(body, "data: [DONE]") {
		t.Errorf("failure must be final with no success/DONE: %s", body)
	}
	terminal := failed[0]
	if terminal.Get("response.status").String() != "failed" {
		t.Errorf("missing failed response status: %s", terminal.Raw)
	}
	errNode := terminal.Get("response.error")
	if errNode.Get("code").String() == "" || errNode.Get("message").String() == "" {
		t.Errorf("missing retryable error code/message: %s", terminal.Raw)
	}
	message := strings.ToLower(errNode.Get("message").String())
	if !errNode.Get("retryable").Bool() && !strings.Contains(message, "retry") && !strings.Contains(message, "try again") {
		t.Errorf("terminal does not communicate retryability: %s", terminal.Raw)
	}
	if errNode.Get("request_id").String() != codexTerminalHTTPRequestID {
		t.Errorf("terminal missing gateway-generated request ID: %s", terminal.Raw)
	}
	if partial && !strings.Contains(body, codexTerminalHTTPDelta) {
		t.Errorf("meaningful partial output was lost: %s", body)
	}
}

// Keep reason: incident #17478; these transport cuts cannot be forced cheaply
// and reliably against the live Codex service from an ordinary client flow.
func TestCodexTerminalHTTP(t *testing.T) {
	for _, client := range []struct{ name, ua string }{
		{"official-codex", "codex_cli_rs/0.100.0"}, {"pi", "pi/0.60.0"},
	} {
		for _, buffering := range []bool{false, true} {
			for _, mode := range []string{"midstream-eof", "before-event-eof", "read-error", "overloaded", "before-output-overloaded", "completed"} {
				t.Run(fmt.Sprintf("%s/buffering=%t/%s", client.name, buffering, mode), func(t *testing.T) {
					var calls atomic.Int32
					fixture := codexTerminalHTTPSSE(codexTerminalHTTPCreated, codexTerminalHTTPDelta)
					switch mode {
					case "before-event-eof":
						fixture = ""
					case "overloaded", "before-output-overloaded":
						if mode == "before-output-overloaded" {
							fixture = codexTerminalHTTPSSE(codexTerminalHTTPCreated)
						}
						fixture += codexTerminalHTTPSSE(`{"type":"error","error":{"type":"service_unavailable_error","code":"server_is_overloaded","message":"Our servers are currently overloaded. Please try again later. api_key=RAW_SECRET_17478_DO_NOT_FORWARD"}}`)
					case "completed":
						fixture += codexTerminalHTTPSSE(codexTerminalHTTPCompleted)
					}
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						codexTerminalHTTPAssertRequest(t, r)
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, fixture)
					}))
					defer server.Close()
					var secondCalls atomic.Int32
					endpoints := []string{server.URL}
					partial := mode == "midstream-eof" || mode == "read-error" || mode == "overloaded"
					if partial {
						second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							secondCalls.Add(1)
							codexTerminalHTTPAssertRequest(t, r)
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = io.WriteString(w, codexTerminalHTTPSSE(codexTerminalHTTPCreated, codexTerminalHTTPDelta, codexTerminalHTTPCompleted))
						}))
						defer second.Close()
						endpoints = append(endpoints, second.URL)
					}
					manager := codexTerminalHTTPManager(t, buffering, endpoints...)
					var readTransport *codexTerminalHTTPReadTransport
					if mode == "read-error" {
						readTransport = &codexTerminalHTTPReadTransport{t: t, primaryURL: server.URL}
						manager.SetRoundTripperProvider(readTransport)
					}
					recorder := codexTerminalHTTPGateway(t, manager, client.ua)
					attempts := calls.Load()
					if readTransport != nil {
						attempts = readTransport.calls.Load()
					}
					if attempts != 1 || secondCalls.Load() != 0 {
						t.Errorf("upstream attempts = %d/%d, want 1/0 (no replay after partial output)", attempts, secondCalls.Load())
					}
					if mode == "completed" {
						if recorder.Code != http.StatusOK || recorder.Body.String() != codexTerminalHTTPCompletedBaseline() {
							t.Errorf("completed stream changed from captured HEAD baseline\nwant: %q\n got: %q", codexTerminalHTTPCompletedBaseline(), recorder.Body.String())
						}
						return
					}
					codexTerminalHTTPAssertFailed(t, recorder, mode != "before-event-eof" && mode != "before-output-overloaded")
				})
			}
		}
	}
}

func TestCodexTerminalHTTPSafePreOutputFailover(t *testing.T) {
	for _, client := range []string{"codex_cli_rs/0.100.0", "pi/0.60.0"} {
		t.Run(client, func(t *testing.T) {
			var firstCalls, secondCalls atomic.Int32
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				firstCalls.Add(1)
				codexTerminalHTTPAssertRequest(t, r)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, codexTerminalHTTPSSE(codexTerminalHTTPCreated, codexOverloadEvent))
			}))
			defer first.Close()
			fixture := codexTerminalHTTPSSE(codexTerminalHTTPCreated, codexTerminalHTTPDelta, codexTerminalHTTPCompleted)
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				secondCalls.Add(1)
				codexTerminalHTTPAssertRequest(t, r)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, fixture)
			}))
			defer second.Close()
			manager := codexTerminalHTTPManager(t, true, first.URL, second.URL)
			recorder := codexTerminalHTTPGateway(t, manager, client)
			if firstCalls.Load() != 1 || secondCalls.Load() != 1 || recorder.Code != http.StatusOK || recorder.Body.String() != codexTerminalHTTPCompletedBaseline() {
				t.Errorf("safe pre-output failover changed: attempts=%d/%d status=%d body=%s", firstCalls.Load(), secondCalls.Load(), recorder.Code, recorder.Body.String())
			}
		})
	}
}
