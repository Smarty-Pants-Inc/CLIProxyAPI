package handlers_test

import (
	"strings"
	"testing"
)

// Trust boundary/recorded catch: PR #174 must not invent a failure after a
// valid multiline success terminal. Exercise every upstream/client pairing,
// including an unterminated final line and the Codex bootstrap handoff.
func TestMultilineStreamCompletionHTTP(t *testing.T) {
	for _, provider := range []string{"compat", "codex", "claude"} {
		for _, client := range []string{"chat", "responses", "messages"} {
			for _, mode := range []string{"plain", "crlf", "last_line_eof"} {
				t.Run(provider+"/"+client+"/"+mode, func(t *testing.T) {
					var native string
					body := reviewRequest(t, provider, client, func(first, terminal string) string {
						// Split JSON at an object boundary, not inside a JSON string.
						terminal = strings.ReplaceAll(terminal, "data: {", "data: {\ndata: ")
						native = first + terminal
						switch mode {
						case "crlf":
							return strings.ReplaceAll(native, "\n", "\r\n")
						case "last_line_eof":
							return strings.TrimRight(native, "\n")
						default:
							return native
						}
					})
					if strings.Contains(body, "upstream_stream_incomplete") || strings.Contains(body, "event: error") || strings.Contains(body, "event: response.failed") {
						t.Fatalf("valid multiline terminal reported as failure: %s", body)
					}
					expected := map[string]string{"chat": "[DONE]", "responses": "response.completed", "messages": "message_stop"}[client]
					if !strings.Contains(body, expected) {
						t.Fatalf("missing terminal %s: %s", expected, body)
					}
					if provider == "claude" && client == "messages" && mode == "plain" && body != native {
						t.Fatalf("native multiline passthrough bytes changed:\ngot %q\nwant %q", body, native)
					}
				})
			}
		}
	}
}
