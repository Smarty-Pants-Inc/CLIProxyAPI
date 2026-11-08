package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestPoolNativeWebsocketExecutorDeniesGlobalModeWithoutContext(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		cfg := &config.Config{}
		if orphan {
			cfg.APIKeyPolicies = []config.APIKeyPolicy{{Pool: "invalid-orphan"}}
		} else {
			pools := []config.AccountPool{}
			cfg.AccountPools = &pools
		}
		var calls atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
		t.Cleanup(upstream.Close)
		a := &core.Auth{ID: "fake", Provider: "codex", Attributes: map[string]string{"api_key": "fake-key", "base_url": upstream.URL}}
		e := NewCodexWebsocketsExecutor(cfg)
		req := ex.Request{Model: "fake-model", Payload: []byte(`{"model":"fake-model","input":"test"}`)}
		_, err := e.Execute(context.Background(), a, req, ex.Options{})
		var typed interface{ StatusCode() int }
		if !errors.As(err, &typed) || typed.StatusCode() != 503 {
			t.Fatalf("orphan=%v Execute error=%v", orphan, err)
		}
		_, err = e.ExecuteStream(context.Background(), a, req, ex.Options{Stream: true})
		if !errors.As(err, &typed) || typed.StatusCode() != 503 {
			t.Fatalf("orphan=%v ExecuteStream error=%v", orphan, err)
		}
		if calls.Load() != 0 {
			t.Fatalf("unadmitted native websocket sent %d times", calls.Load())
		}
	}
}
