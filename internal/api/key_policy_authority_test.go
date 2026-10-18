package api

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
)

// Use the full client path with no header:Host attribute. This also records the
// ordinary NewRequest behavior shared with r146, separately from empty-Host tests.
func TestKeyPolicyClaudeBaseURLAuthority(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/chat/completions", "/v1/responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", path, stream), func(t *testing.T) {
				var calls atomic.Int32
				var mu sync.Mutex
				var last []byte
				upstream := fakeClaudeUpstream(t, http.StatusOK, &calls, &last, &mu, "verified-A", func(r *http.Request) {
					if want := r.Context().Value(http.LocalAddrContextKey).(net.Addr).String(); r.Host != want {
						t.Errorf("wire authority=%q, want base_url authority %q", r.Host, want)
					}
				})
				defer upstream.Close()
				cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, nil, nil)
				server := newTestServerWithConfig(t, cfg)
				server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
				registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
				rr := sendPolicied(server, path, policyBody(path, policyClaudeModel, stream))
				if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "hi") || calls.Load() != 1 {
					t.Fatalf("base_url-only auth: status=%d body=%s calls=%d", rr.Code, rr.Body.String(), calls.Load())
				}
			})
		}
	}
}
