package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
)

// Policy admission must retain the operator's response-header setting across
// all supported protocols, including headers delivered before streaming bytes.
func TestKeyPolicyClaudePassthroughHeaders(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/chat/completions", "/v1/responses"} {
		for _, stream := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/stream=%t/enabled=%t", path, stream, enabled), func(t *testing.T) {
					var calls atomic.Int32
					var mu sync.Mutex
					var last []byte
					upstream := fakeClaudeUpstream(t, http.StatusOK, &calls, &last, &mu, "verified-A")
					defer upstream.Close()
					cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, nil, nil)
					cfg.PassthroughHeaders = enabled
					cfg.Streaming.BootstrapRetries = 3
					server := newTestServerWithConfig(t, cfg)
					server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
					registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
					rr := sendPolicied(server, path, policyBody(path, policyClaudeModel, stream))
					if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "hi") || calls.Load() != 1 {
						t.Fatalf("status=%d body=%s calls=%d", rr.Code, rr.Body.String(), calls.Load())
					}
					want := ""
					if enabled {
						want = "42"
					}
					if got := rr.Header().Get("X-Ratelimit-Remaining"); got != want {
						t.Errorf("upstream response header=%q, want %q (passthrough-headers=%t)", got, want, enabled)
					}
					if server.handlers.Cfg.Streaming.BootstrapRetries != 3 || server.handlers.Cfg.PassthroughHeaders != enabled {
						t.Error("policy admission mutated shared SDK settings")
					}
				})
			}
		}
	}
}

// Copying SDK settings must not re-enable bootstrap retries for a policy key.
func TestKeyPolicyClaudeNoBootstrapRetries(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/chat/completions", "/v1/responses"} {
		t.Run(path, func(t *testing.T) {
			var calls atomic.Int32
			var mu sync.Mutex
			var last []byte
			upstream := fakeClaudeUpstream(t, http.StatusServiceUnavailable, &calls, &last, &mu, "verified-A")
			defer upstream.Close()
			cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, nil, nil)
			cfg.Streaming.BootstrapRetries = 3
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
			rr := sendPolicied(server, path, policyBody(path, policyClaudeModel, true))
			if rr.Code != http.StatusServiceUnavailable || calls.Load() != 1 {
				t.Fatalf("bootstrap retried: status=%d body=%s calls=%d", rr.Code, rr.Body.String(), calls.Load())
			}
			if server.handlers.Cfg.Streaming.BootstrapRetries != 3 {
				t.Fatal("policy admission disabled retries in the shared SDK config")
			}
		})
	}
}
