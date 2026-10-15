package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
)

// cancelOnWrite cancels the client request once the downstream body contains marker.
type cancelOnWrite struct {
	*httptest.ResponseRecorder
	marker string
	cancel context.CancelFunc
	fired  bool
}

func (w *cancelOnWrite) Write(b []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(b)
	if w.cancel != nil && !w.fired && strings.Contains(w.Body.String(), w.marker) {
		w.fired = true
		w.cancel()
	}
	return n, err
}

func (w *cancelOnWrite) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

// An aborted Claude stream reports only partial usage (message_start and a
// message_delta without message_stop). Partial usage must not count as
// metered: the operation takes the fail-safe path and the key's daily token
// budget closes, so the next request is 429 even under a generous cap.
func TestKeyPolicyClaudeAbortedStreamFailsClosed(t *testing.T) {
	for _, path := range []string{"/v1/responses", "/v1/messages", "/v1/chat/completions"} {
		for _, abort := range []string{"no message_stop", "client disconnect"} {
			t.Run(path+"/"+abort, func(t *testing.T) {
				release := make(chan struct{})
				defer close(release)
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n", policyClaudeModel)
					fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
					fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n")
					fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":null},\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}\n\n")
					w.(http.Flusher).Flush()
					if abort == "client disconnect" {
						select {
						case <-r.Context().Done():
						case <-release:
						}
					}
					// Return without message_stop.
				}))
				defer upstream.Close()
				tokenCap, requestCap := int64(1000), int64(10)
				cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tokenCap, &requestCap)
				server := newTestServerWithConfig(t, cfg)
				server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
				registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
				body := policyBody(path, policyClaudeModel, true)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				w := &cancelOnWrite{ResponseRecorder: httptest.NewRecorder()}
				if abort == "client disconnect" {
					// Disconnect only after the client has the partial usage frame.
					w.marker, w.cancel = "message_delta", cancel
					switch path {
					case "/v1/responses":
						w.marker = "output_text.delta"
					case "/v1/chat/completions":
						w.marker = `"content":"hi"`
					}
				}
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer test-key")
				server.engine.ServeHTTP(w, req)
				if abort == "client disconnect" && !w.fired {
					t.Fatalf("client never saw %q before disconnect: %s", w.marker, w.Body.String())
				}

				// Partial usage is 7 of a 1000 cap: only the fail-safe yields 429.
				next := sendPolicied(server, path, body)
				if next.Code != http.StatusTooManyRequests {
					t.Fatalf("next request status=%d, want 429 (fail-safe): %s", next.Code, next.Body.String())
				}
			})
		}
	}
}
