package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestAPIKeySingleAttemptTruncated400KeepsResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Length", "1000")
		w.Header().Set("Retry-After", "23")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":{"code":"context_length_exceeded"}}`))
	}))
	defer server.Close()
	exec := NewCodexExecutor(&config.Config{})
	a := &cliproxyauth.Auth{ID: "truncated-error", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "synthetic"}}
	// Non-single policies must not retry a 400 whose body is truncated either.
	ctx := coreexecutor.WithClientExecutionPolicy(context.Background(), "gpt-5.4", false)
	_, err := exec.Execute(ctx, a, coreexecutor.Request{Model: "gpt-5.4", Payload: []byte(`{"model":"gpt-5.4","input":"hello"}`)}, coreexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")})
	var raw *coreexecutor.ClientUpstreamError
	if !errors.As(err, &raw) || raw.Status != 400 || string(raw.Body) != `{"error":{"code":"context_length_exceeded"}}` || raw.Header.Get("Retry-After") != "23" || !raw.Terminal || calls.Load() != 1 {
		t.Fatalf("response lost: %v (%d calls)", err, calls.Load())
	}
}
