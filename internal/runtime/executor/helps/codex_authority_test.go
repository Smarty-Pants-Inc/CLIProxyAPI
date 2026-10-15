package helps

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The credential fence must use the same effective authority as net/http, while
// preserving explicit Host, custom-header and final-endpoint restrictions.
func TestKeyPolicyEffectiveAuthority(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			name, host, headerHost, configuredHost string
			want                                   int
		}{
			{name: "empty_host", want: http.StatusOK},
			{name: "matching_host", host: "endpoint", want: http.StatusOK},
			{name: "mismatched_host", host: "other.example", want: http.StatusServiceUnavailable},
			{name: "mismatched_header_host", headerHost: "other.example", want: http.StatusServiceUnavailable},
			{name: "configured_host", host: "tenant.example", headerHost: "tenant.example", configuredHost: "tenant.example", want: http.StatusOK},
			{name: "missing_configured_host", configuredHost: "tenant.example", want: http.StatusServiceUnavailable},
			{name: "dynamic_configured_host", configuredHost: "$X-Route", want: http.StatusServiceUnavailable},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				var calls atomic.Int32
				path := "/responses"
				if provider == "claude" {
					path = "/v1/messages?beta=true"
				}
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					wantHost := tc.configuredHost
					if wantHost == "" {
						wantHost = r.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
					}
					if r.Host != wantHost || r.URL.RequestURI() != path {
						t.Errorf("wire authority/path = %q %q, want %q %q", r.Host, r.URL.RequestURI(), wantHost, path)
					}
					if r.Header.Get("Authorization") != "Bearer synthetic-credential" {
						t.Error("upstream did not receive the bound credential")
					}
					w.WriteHeader(http.StatusOK)
					_, _ = io.WriteString(w, "bound upstream")
				}))
				defer upstream.Close()
				m := auth.NewManager(nil, nil, nil)
				m.SetConfig(&config.Config{})
				ctx, done, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{{KeySHA256: strings.Repeat("a", 64)}}, "test-model")
				if err != nil {
					t.Fatal(err)
				}
				defer done()
				a := &auth.Auth{Provider: provider, Attributes: map[string]string{"base_url": upstream.URL}}
				if tc.configuredHost != "" {
					a.Attributes["header:Host"] = tc.configuredHost
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL+path, strings.NewReader(`{"model":"test-model"}`))
				if err != nil {
					t.Fatal(err)
				}
				// NewRequest populates Host, but a manually constructed or cleared
				// Host is also valid: net/http falls back to URL.Host on the wire.
				req.Host = tc.host
				if tc.host == "endpoint" {
					req.Host = req.URL.Host
				}
				if tc.headerHost != "" {
					req.Header.Set("Host", tc.headerHost)
				}
				req.Header.Set("Authorization", "Bearer synthetic-credential")
				resp, err := NewUtlsHTTPClient(ctx, &config.Config{}, a, 0).Do(req)
				if resp != nil {
					defer func() {
						if errClose := resp.Body.Close(); errClose != nil {
							t.Error(errClose)
						}
					}()
				}
				if tc.want != http.StatusOK {
					var policyErr *auth.Error
					if !errors.As(err, &policyErr) || policyErr.StatusCode() != tc.want || policyErr.Code != "api_key_policy_unavailable" || calls.Load() != 0 {
						t.Fatalf("unsafe authority: error=%v calls=%d", err, calls.Load())
					}
					return
				}
				if err != nil {
					t.Fatalf("effective authority refused: %v (upstream calls=%d)", err, calls.Load())
				}
				body, errRead := io.ReadAll(resp.Body)
				if errRead != nil || resp.StatusCode != tc.want || string(body) != "bound upstream" || calls.Load() != 1 {
					t.Fatalf("response=%d %q error=%v calls=%d", resp.StatusCode, body, errRead, calls.Load())
				}
			})
		}
	}
}
