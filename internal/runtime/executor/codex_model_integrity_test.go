package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexHTTPModelIntegrityTerminal(t *testing.T) {
	for _, terminal := range []string{"response.completed", "response.incomplete"} {
		for _, model := range []string{"gpt-6-astra", "wrong-model", ""} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/model=%s/stream=%t", terminal, model, stream), func(t *testing.T) {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "text/event-stream")
						field := ""
						if model != "" {
							field = fmt.Sprintf(",\"model\":%q", model)
						}
						fmt.Fprintf(w, "data: {\"type\":%q,\"response\":{\"id\":\"proof\"%s,\"output\":[{\"type\":\"function_call\",\"call_id\":\"call-proof\",\"name\":\"DISALLOWED_TOOL\",\"arguments\":\"{}\"},{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"DISALLOWED_TEXT\"}]}]}}\n\n", terminal, field)
					}))
					defer server.Close()
					e := NewCodexExecutor(&config.Config{})
					credential := &auth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL}}
					req := core.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","input":"proof"}`)}
					opts := core.Options{SourceFormat: translator.FromString("codex")}
					var payload []byte
					var err error
					if stream {
						var result *core.StreamResult
						result, err = e.ExecuteStream(context.Background(), credential, req, opts)
						if err == nil {
							for chunk := range result.Chunks {
								payload = append(payload, chunk.Payload...)
								if chunk.Err != nil {
									err = chunk.Err
								}
							}
						}
					} else {
						var result core.Response
						result, err = e.Execute(context.Background(), credential, req, opts)
						payload = result.Payload
					}
					if model != "gpt-6-astra" {
						if err == nil || !strings.Contains(err.Error(), "model_mismatch") {
							t.Fatalf("want model_mismatch, got %v", err)
						}
						if len(payload) != 0 {
							t.Fatalf("unverified response escaped: %s", payload)
						}
					} else if err != nil && err != io.EOF {
						t.Fatal(err)
					} else if !strings.Contains(string(payload), "DISALLOWED_TOOL") || !strings.Contains(string(payload), "DISALLOWED_TEXT") {
						t.Fatalf("matching response lost: %s", payload)
					}
				})
			}
		}
	}
}
