package helps

import (
	"context"
	"net/http"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type poolHTTPTransport struct {
	base http.RoundTripper
	deny bool
}

func poolHTTPError() error {
	return &cliproxyauth.Error{Code: "api_key_pool_path_unavailable", Message: "api_key_pool_path_unavailable", HTTPStatus: 503}
}
func (t poolHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.deny || !cliproxyauth.KeyPolicyFromContext(req.Context()).IsPoolOperation() {
		return nil, poolHTTPError()
	}
	if err := cliproxyauth.CheckNativePoolSend(req); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err == nil && resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, poolHTTPError()
	}
	return resp, err
}

// NativePoolConfigured also recognizes an invalid orphan pooled policy so a
// direct native executor cannot turn an invalid initial SDK snapshot into OFF.
func NativePoolConfigured(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.AccountPools != nil {
		return true
	}
	for _, policy := range cfg.APIKeyPolicies {
		if policy.Pool != "" {
			return true
		}
	}
	return false
}

func fenceNativePoolClient(ctx context.Context, cfg *config.Config, client *http.Client) *http.Client {
	if !NativePoolConfigured(cfg) && !cliproxyauth.KeyPolicyFromContext(ctx).IsPoolOperation() {
		return client
	}
	injected := false
	if ctx != nil {
		_, injected = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}
	_, standard := http.DefaultTransport.(*http.Transport)
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	client.Transport = poolHTTPTransport{base: base, deny: injected || !standard}
	client.Timeout = 0
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return poolHTTPError() }
	return client
}

// NewNativePoolAcquisitionClient has no caller/context transport injection and
// permits only official native control-plane requests, never business paths.
func NewNativePoolAcquisitionClient(cfg *config.Config, a *cliproxyauth.Auth, provider string) *http.Client {
	// Only this official-endpoint acquisition client bypasses the business
	// admission fence; the independent control-plane transport below replaces it.
	if cfg != nil {
		cfg = cfg.CloneForRuntime()
		cfg.AccountPools = nil
		cfg.APIKeyPolicies = nil
	}
	client := NewUtlsHTTPClient(context.Background(), cfg, a, 0)
	_, standard := http.DefaultTransport.(*http.Transport)
	client.Transport = poolAcquisitionTransport{base: client.Transport, provider: provider, deny: !standard}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return poolHTTPError() }
	return client
}

type poolAcquisitionTransport struct {
	base     http.RoundTripper
	provider string
	deny     bool
}

func (t poolAcquisitionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u := req.URL
	if t.deny || u == nil || u.User != nil || u.Scheme != "https" || u.Opaque != "" || u.RawQuery != "" || u.RawPath != "" || u.Fragment != "" || (req.Host != "" && req.Host != u.Host) {
		return nil, poolHTTPError()
	}
	allowed := t.provider == "codex" && req.Method == http.MethodPost && u.String() == codexauth.TokenURL
	if t.provider == "claude" {
		allowed = (req.Method == http.MethodGet && u.String() == claudeauth.ProfileURL) || (req.Method == http.MethodPost && u.String() == claudeauth.TokenURL)
	}
	if !allowed {
		return nil, poolHTTPError()
	}
	req.GetBody = nil
	resp, err := t.base.RoundTrip(req)
	if err == nil && resp != nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		return nil, poolHTTPError()
	}
	return resp, err
}
