package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func requireSingleAttemptUpstreamError(t *testing.T, err error, status int, body, retryAfter string) {
	t.Helper()
	var upstream interface {
		StatusCode() int
		ResponseBody() []byte
		Headers() http.Header
	}
	if !errors.As(err, &upstream) {
		t.Fatalf("error %T %v does not preserve upstream response", err, err)
	}
	if upstream.StatusCode() != status {
		t.Fatalf("status=%d, want %d", upstream.StatusCode(), status)
	}
	if string(upstream.ResponseBody()) != body {
		t.Fatalf("body=%q, want exact %q", upstream.ResponseBody(), body)
	}
	if got := upstream.Headers().Get("Retry-After"); got != retryAfter {
		t.Fatalf("Retry-After=%q, want %q", got, retryAfter)
	}
	if got := upstream.Headers().Values("X-Synthetic-Upstream"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("upstream headers lost: %v", upstream.Headers())
	}
	if got := upstream.Headers().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}
}

func TestAPIKeySingleAttemptCodexPreservesUpstreamErrors(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, status := range []int{400, 429, 503} {
			for _, single := range []bool{false, true} {
				t.Run(fmt.Sprintf("stream=%v/status=%d/single=%v", stream, status, single), func(t *testing.T) {
					body := fmt.Sprintf("{\n  \"error\": {\"code\": \"context_length_exceeded\", \"message\": \"synthetic upstream %d\"}\n}\n", status)
					const retryAfter = "17"
					var calls atomic.Int32
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						payload, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read request: %v", err)
						}
						if got := gjson.GetBytes(payload, "model").String(); got != "gpt-5.4" {
							t.Errorf("wire model=%q", got)
						}
						w.Header().Set("Content-Type", "application/json")
						w.Header().Set("Retry-After", retryAfter)
						w.Header().Add("X-Synthetic-Upstream", "first")
						w.Header().Add("X-Synthetic-Upstream", "second")
						w.WriteHeader(status)
						_, _ = io.WriteString(w, body)
					}))
					defer server.Close()
					exec := NewCodexExecutor(&config.Config{})
					auth := &cliproxyauth.Auth{ID: "single-http", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "synthetic"}}
					ctx := coreexecutor.WithClientExecutionPolicy(context.Background(), "gpt-5.4", single)
					req := coreexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":"hello"}`)}
					opts := coreexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: stream}
					var err error
					if stream {
						_, err = exec.ExecuteStream(ctx, auth, req, opts)
					} else {
						_, err = exec.Execute(ctx, auth, req, opts)
					}
					requireSingleAttemptUpstreamError(t, err, status, body, retryAfter)
					if got := calls.Load(); got != 1 {
						t.Fatalf("upstream calls=%d, want 1", got)
					}
				})
			}
		}
	}
}

func TestAPIKeySingleAttemptCodexRejectsDifferentWireModel(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(503) }))
			defer server.Close()
			exec := NewCodexExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{ID: "single-wire-model", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "synthetic"}}
			ctx := coreexecutor.WithClientExecutionPolicy(context.Background(), "original-client-model", true)
			req := coreexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":"hello"}`)}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: stream}
			var err error
			if stream {
				_, err = exec.ExecuteStream(ctx, auth, req, opts)
			} else {
				_, err = exec.Execute(ctx, auth, req, opts)
			}
			var policyErr *coreexecutor.ClientExecutionPolicyError
			if !errors.As(err, &policyErr) {
				t.Fatalf("error=%T %v, want model policy rejection", err, err)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("different model reached upstream %d times", got)
			}
		})
	}
}

func TestAPIKeySingleAttemptCodexWebsocket426NeverFallsBack(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, single := range []bool{false, true} {
			t.Run(fmt.Sprintf("stream=%v/single=%v", stream, single), func(t *testing.T) {
				var calls, httpCalls atomic.Int32
				const body = `{"error":{"message":"synthetic websocket upgrade required"}}`
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Upgrade") != "websocket" {
						httpCalls.Add(1)
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("Retry-After", "19")
					w.Header().Add("X-Synthetic-Upstream", "first")
					w.Header().Add("X-Synthetic-Upstream", "second")
					w.WriteHeader(http.StatusUpgradeRequired)
					_, _ = io.WriteString(w, body)
				}))
				defer server.Close()
				exec := NewCodexWebsocketsExecutor(&config.Config{})
				auth := &cliproxyauth.Auth{ID: "single-ws-426", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "websockets": "true", "api_key": "synthetic"}}
				ctx := coreexecutor.WithClientExecutionPolicy(context.Background(), "gpt-5.4", single)
				req := coreexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":"hello"}`)}
				opts := coreexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: stream}
				var err error
				if stream {
					_, err = exec.ExecuteStream(ctx, auth, req, opts)
				} else {
					_, err = exec.Execute(ctx, auth, req, opts)
				}
				requireSingleAttemptUpstreamError(t, err, 426, body, "19")
				if calls.Load() != 1 || httpCalls.Load() != 0 {
					t.Fatalf("calls=%d HTTP fallback=%d, want one WS handshake only", calls.Load(), httpCalls.Load())
				}
			})
		}
	}
}
