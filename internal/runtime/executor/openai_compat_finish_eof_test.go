package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Recorded catch: PR #174 r7. Real HTTP EOF must complete translated streams
// only after every observed choice finishes, even if the provider omits [DONE].
func TestOpenAICompatStreamFinishReasonEOF(t *testing.T) {
	chunk := func(choices string) string {
		return fmt.Sprintf("data: {\"id\":\"chat-eof\",\"model\":\"fixture\",\"choices\":%s}\n\n", choices)
	}
	first := chunk(`[{"index":0,"delta":{"role":"assistant","content":"hello"},"finish_reason":null}]`)
	finish := chunk(`[{"index":0,"delta":{},"finish_reason":"stop"}]`)
	second := chunk(`[{"index":1,"delta":{"content":"other"},"finish_reason":null}]`)
	finishSecond := chunk(`[{"index":1,"delta":{},"finish_reason":"length"}]`)
	usage := "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n"
	for _, client := range []string{"openai", "openai-response", "claude", "gemini"} {
		for _, tc := range []struct {
			name, wire          string
			complete, readError bool
		}{
			{name: "finish_without_done", wire: first + finish, complete: true},
			{name: "finish_last_frame_without_separator", wire: first + strings.TrimSpace(finish), complete: true},
			{name: "late_usage", wire: first + finish + usage, complete: true},
			{name: "both_choices_finished", wire: first + second + finishSecond + finish, complete: true},
			{name: "one_choice_unfinished", wire: first + second + finish},
			{name: "later_choice_unfinished", wire: first + finish + second},
			{name: "null_finish", wire: first},
			{name: "empty_string_finish", wire: first + chunk(`[{"index":0,"delta":{},"finish_reason":""}]`)},
			{name: "absent_finish", wire: chunk(`[{"index":0,"delta":{"content":"hello"}}]`)},
			{name: "usage_only", wire: usage},
			{name: "empty", wire: ""},
			{name: "explicit_done", wire: first + finish + "data: [DONE]\n\n", complete: true},
			{name: "read_error_after_finish", wire: first + finish, readError: true},
			{name: "error_event_after_finish", wire: first + finish + "event: error\n\n"},
		} {
			t.Run(client+"/"+tc.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					if tc.readError {
						w.Header().Set("Content-Length", "100000")
					}
					fmt.Fprint(w, tc.wire)
				}))
				defer server.Close()
				executor := NewOpenAICompatExecutor("compat", &config.Config{})
				auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": server.URL, "api_key": "fixture"}}
				req := cliproxyexecutor.Request{Model: "fixture", Payload: []byte(`{"model":"fixture","messages":[{"role":"user","content":"hello"}],"stream":true}`)}
				result, err := executor.ExecuteStream(context.Background(), auth, req, cliproxyexecutor.Options{
					SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FromString(client), Stream: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				var body strings.Builder
				var streamErr error
				for chunk := range result.Chunks {
					body.Write(chunk.Payload)
					if chunk.Err != nil {
						streamErr = chunk.Err
					}
				}
				// Chat executors yield JSON payloads; HTTP handlers append [DONE].
				marker := map[string]string{"openai": `"content":"hello"`, "openai-response": `"type":"response.completed"`, "claude": `"type":"message_stop"`, "gemini": "finishReason"}[client]
				if tc.complete {
					if streamErr != nil || !strings.Contains(body.String(), marker) {
						t.Fatalf("complete EOF: err=%v body=%s", streamErr, body.String())
					}
					if (client == "openai-response" || client == "claude") && strings.Count(body.String(), marker) != 1 {
						t.Fatalf("duplicate completion: %s", body.String())
					}
					if tc.name == "late_usage" && client == "openai-response" && !strings.Contains(body.String(), `"total_tokens":5`) {
						t.Fatalf("lost late usage: %s", body.String())
					}
				} else {
					if streamErr == nil || !strings.Contains(streamErr.Error(), "closed before [DONE]") {
						t.Fatalf("incomplete EOF: err=%v body=%s", streamErr, body.String())
					}
					if strings.Contains(body.String(), "response.completed") || strings.Contains(body.String(), "[DONE]") {
						t.Fatalf("incomplete stream finalized: %s", body.String())
					}
				}
			})
		}
	}
}
