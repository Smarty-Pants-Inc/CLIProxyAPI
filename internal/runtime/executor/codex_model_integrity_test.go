package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexUnverifiedFailureDoesNotFlush(t *testing.T) {
	for _, transport := range []string{"http", "websocket", "websocket-nonstream", "duplex"} {
		t.Run(transport, func(t *testing.T) {
			frames := []string{
				`{"type":"response.created","response":{"id":"proof"}}`,
				`{"type":"response.output_text.delta","delta":"DISALLOWED_TEXT"}`,
				`{"type":"response.function_call_arguments.delta","delta":"DISALLOWED_TOOL"}`,
				`{"type":"response.failed","response":{"id":"proof","error":{"type":"invalid_request_error","message":"rejected"}}}`,
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if transport == "http" {
					w.Header().Set("Content-Type", "text/event-stream")
					for _, frame := range frames {
						fmt.Fprintf(w, "data: %s\n\n", frame)
					}
					return
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err = conn.ReadMessage(); err != nil {
					return
				}
				for _, frame := range frames {
					if err = conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
						return
					}
				}
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if transport == "duplex" {
				ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), make(chan core.WebsocketInput))
			}
			credential := &auth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL, "websockets": "true"}}
			req := core.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","input":"proof"}`)}
			opts := core.Options{SourceFormat: translator.FromString("codex"), Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}, WebSocketResponseObserver: func(_ context.Context, ev core.WebSocketResponseEvent) {
				t.Errorf("unverified observer event escaped: %s", ev.Payload)
			}}
			var result *core.StreamResult
			var err error
			if transport == "http" {
				result, err = NewCodexExecutor(&config.Config{}).ExecuteStream(ctx, credential, req, opts)
			} else {
				e := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{ResponseSteering: true}})
				e.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				defer e.CloseExecutionSession(t.Name())
				if transport == "websocket-nonstream" {
					var response core.Response
					response, err = e.Execute(ctx, credential, req, opts)
					if len(response.Payload) != 0 {
						t.Errorf("unverified nonstream payload escaped: %s", response.Payload)
					}
				} else {
					result, err = e.ExecuteStream(ctx, credential, req, opts)
				}
			}
			if result != nil {
				for chunk := range result.Chunks {
					if len(chunk.Payload) != 0 {
						t.Errorf("unverified payload escaped: %s", chunk.Payload)
					}
					if chunk.Err != nil {
						err = chunk.Err
					}
				}
			}
			if err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}

func TestCodexWebsocketModelFailureReleasesSession(t *testing.T) {
	for _, frame := range []string{
		`{"type":"response.completed","response":{"model":"wrong-model","output":[]}}`,
		`{"type":"response.completed","response":{"output":[]}}`,
		`{"type":"response.output_text.delta","delta":"` + strings.Repeat("x", codexBootstrapMaxBufferedBytes) + `"}`,
	} {
		t.Run(fmt.Sprintf("bytes=%d", len(frame)), func(t *testing.T) {
			var attempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err = conn.ReadMessage(); err != nil {
					return
				}
				response := frame
				if attempts.Add(1) > 1 {
					response = `{"type":"response.completed","response":{"model":"gpt-6-astra","output":[]}}`
				}
				_ = conn.WriteMessage(websocket.TextMessage, []byte(response))
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			e := NewCodexWebsocketsExecutor(&config.Config{})
			e.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer e.CloseExecutionSession(t.Name())
			credential := &auth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL}}
			disconnected := e.UpstreamDisconnectChan(t.Name())
			for attempt := 0; attempt < 2; attempt++ {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				result, err := e.ExecuteStream(ctx, credential, core.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","input":"proof"}`)}, core.Options{SourceFormat: translator.FromString("codex"), Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}, WebSocketResponseObserver: func(_ context.Context, ev core.WebSocketResponseEvent) {
					if !strings.Contains(string(ev.Payload), `"model":"gpt-6-astra"`) {
						t.Errorf("unverified observer payload: %d bytes", len(ev.Payload))
					}
				}})
				if attempt == 0 {
					cancel()
					if result != nil || err == nil || !strings.Contains(err.Error(), "model_mismatch") {
						t.Fatalf("attempt %d: result=%v err=%v", attempt, result, err)
					}
					select {
					case <-disconnected:
						t.Fatal("retryable refusal closed downstream socket")
					default:
					}
				} else {
					if err != nil {
						cancel()
						t.Fatal(err)
					}
					var payload []byte
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Error(chunk.Err)
						}
						payload = append(payload, chunk.Payload...)
					}
					cancel()
					if !strings.Contains(string(payload), `"model":"gpt-6-astra"`) {
						t.Fatalf("same-model retry failed: %s", payload)
					}
				}
			}
		})
	}
}

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
