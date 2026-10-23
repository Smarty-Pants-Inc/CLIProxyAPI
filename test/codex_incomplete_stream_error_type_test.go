package test

import (
	"context"
	"encoding/json"
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
	openaihandlers "github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// TestCodexIncompleteStreamIsNotTypedAsInvalidRequest drives the real /v1/responses
// handler against an upstream that stops mid function-call arguments without ever
// sending response.completed, which is the failure Codex clients see in the wild.
//
// The emitted terminal frame must not claim the client's request was invalid.
// PR #174 deliberately replaces request_timeout/server_error after partial output
// with upstream_stream_incomplete, retryable:true and progress metadata. Missing
// the terminal event is a transient upstream failure: allow the client to retry
// the turn rather than kill a long agent session. It is not invalid_request_error.
func TestCodexIncompleteStreamIsNotTypedAsInvalidRequest(t *testing.T) {
	const model = "gpt-5.4"
	events := []string{
		`{"type":"response.created","response":{"model":"gpt-5.4","id":"resp_truncated"}}`,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"fc_1","type":"function_call","name":"edit","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":"{\"path\":\"app/page.tsx\"","sequence_number":3}`,
		`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":",\"text\":\"editor","sequence_number":4}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		for _, event := range events {
			if _, errWrite := fmt.Fprintf(w, "data: %s\n\n", event); errWrite != nil {
				t.Errorf("write SSE: %v", errWrite)
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		// Return without response.completed: the upstream body simply ends.
	}))
	defer server.Close()

	manager := cliproxyauth.NewManager(nil, &cliproxyauth.RoundRobinSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	cfg := &config.Config{}
	manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))

	const authID = "codex-incomplete-stream"
	registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
	if _, errRegister := manager.Register(context.Background(), &cliproxyauth.Auth{
		ID: authID, Provider: "codex", Status: cliproxyauth.StatusActive,
		Attributes: map[string]string{"base_url": server.URL, "api_key": "incomplete"},
		Metadata:   map[string]any{"disable_cooling": true},
	}); errRegister != nil {
		t.Fatal(errRegister)
	}

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses",
		strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"hello","stream":true}`, model)))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Request.Header.Set("Originator", "codex_cli_rs")

	base := handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager)
	openaihandlers.NewOpenAIResponsesAPIHandler(base).Responses(c)

	body := recorder.Body.String()
	failed := false
	for _, line := range strings.Split(body, "\n") {
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var payload struct {
			Type     string `json:"type"`
			Response struct {
				Status string `json:"status"`
			} `json:"response"`
		}
		if json.Unmarshal([]byte(data), &payload) == nil && payload.Type == "response.failed" {
			if payload.Response.Status != "failed" {
				t.Fatalf("response.failed status = %q, want failed", payload.Response.Status)
			}
			failed = true
		}
	}
	if !failed {
		t.Fatalf("missing response.failed terminal: %s", body)
	}
	detail := terminalStreamErrorDetail(t, body)
	if detail["retryable"] != true {
		t.Fatalf("error.retryable = %v, want true for transient upstream EOF", detail["retryable"])
	}
	if got := detail["code"]; got != "upstream_stream_incomplete" {
		t.Fatalf("error.code = %v, want %q (the stream was cut in transit)", got, "upstream_stream_incomplete")
	}
	if got := detail["type"]; got == "invalid_request_error" {
		t.Fatalf("error.type = %q for a truncated stream: the request was well formed, and this type tells every downstream client not to retry", got)
	}
	if got := detail["type"]; got != "upstream_stream_incomplete" {
		t.Fatalf("error.type = %v, want %q for an interrupted upstream stream", got, "upstream_stream_incomplete")
	}
	if detail["provider"] != "codex" || detail["model"] != model || detail["upstream_status"] != float64(http.StatusOK) {
		t.Fatalf("lost upstream identity/status: %v", detail)
	}
	for _, key := range []string{"partial_bytes", "partial_chunks"} {
		if got, ok := detail[key].(float64); !ok || got <= 0 {
			t.Fatalf("error.%s = %v, want positive partial-output progress", key, detail[key])
		}
	}
}

// terminalStreamErrorDetail returns the error object of the last "error" or
// "response.failed" frame in an SSE body.
func terminalStreamErrorDetail(t *testing.T, body string) map[string]any {
	t.Helper()
	var detail map[string]any
	for _, frame := range strings.Split(body, "\n\n") {
		var data string
		for _, line := range strings.Split(frame, "\n") {
			if rest, ok := strings.CutPrefix(line, "data: "); ok {
				data = rest
			}
		}
		if data == "" {
			continue
		}
		var payload map[string]any
		if errUnmarshal := json.Unmarshal([]byte(data), &payload); errUnmarshal != nil {
			continue
		}
		switch payload["type"] {
		case "error":
			if errorObj, ok := payload["error"].(map[string]any); ok {
				detail = errorObj
			}
		case "response.failed":
			if response, ok := payload["response"].(map[string]any); ok {
				if errorObj, ok := response["error"].(map[string]any); ok {
					detail = errorObj
				}
			}
		}
	}
	if detail == nil {
		t.Fatalf("no terminal error frame in SSE body:\n%s", body)
	}
	return detail
}
