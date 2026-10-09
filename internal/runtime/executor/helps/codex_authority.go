package helps

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The selected credential snapshot fixes both the Responses URL and the wire
// authority. CheckKeyPolicySend separately fences publication and credentials.
// Keep this check at the transport boundary, after custom-header expansion.
type codexAuthorityRoundTripper struct {
	base      http.RoundTripper
	endpoint  *url.URL
	authority string
}

func restrictCodexAuthority(ctx context.Context, auth *cliproxyauth.Auth, base http.RoundTripper) http.RoundTripper {
	if cliproxyauth.KeyPolicyFromContext(ctx) == nil {
		return base
	}
	bound := &codexAuthorityRoundTripper{base: base}
	if auth == nil || auth.Provider != "codex" {
		return bound
	}
	baseURL := auth.Attributes["base_url"]
	if baseURL == "" {
		baseURL = "https://chatgpt.com/backend-api/codex"
	}
	endpoint, errParse := url.Parse(strings.TrimSuffix(baseURL, "/") + "/responses")
	if errParse != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return bound
	}
	authority := endpoint.Host
	staticHost := ""
	for key, value := range auth.Attributes {
		if !strings.HasPrefix(key, "header:") || !strings.EqualFold(strings.TrimSpace(strings.TrimPrefix(key, "header:")), "Host") {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		// Match every dynamic form supported by util.extractCustomHeaders,
		// including embedded session IDs, without trusting resolved equality.
		if strings.HasPrefix(value, "$") || strings.Contains(strings.ToUpper(value), "$CPA-SESSION-ID") || (staticHost != "" && staticHost != value) {
			return bound
		}
		staticHost = value
	}
	if staticHost != "" {
		authority = staticHost
	}
	bound.endpoint, bound.authority = endpoint, authority
	return bound
}

func (t *codexAuthorityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.endpoint == nil || req.URL == nil || req.URL.Opaque != "" || req.URL.User != nil || req.URL.Fragment != "" || req.URL.Scheme != t.endpoint.Scheme || req.URL.Host != t.endpoint.Host || req.URL.String() != t.endpoint.String() || req.Host != t.authority || (req.Header.Get("Host") != "" && req.Header.Get("Host") != t.authority) {
		return nil, &cliproxyauth.Error{Code: "api_key_policy_unavailable", Message: "api_key_policy_unavailable", HTTPStatus: http.StatusServiceUnavailable}
	}
	return t.base.RoundTrip(req)
}
