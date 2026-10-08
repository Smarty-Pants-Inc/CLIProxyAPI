package management

import (
	"context"
	"errors"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/quotaprovider"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (h *Handler) newBuiltinQuotaProvider() *quotaprovider.OAuth {
	provider := quotaprovider.New(h.resolveQuotaCredential)
	provider.Admit = func(req pluginapi.QuotaFetchRequest) bool { return h.builtinQuotaAuth(req) != nil }
	return provider
}

// builtinQuotaAuth admits only OAuth credentials without an explicit per-credential
// quota probe. API-key credentials (often for third-party base URLs) must never
// reach the fixed OAuth usage endpoints.
func (h *Handler) builtinQuotaAuth(req pluginapi.QuotaFetchRequest) *coreauth.Auth {
	auth := h.authByIndex(req.AuthIndex)
	if auth == nil || auth.ID != req.AuthID || auth.Provider != req.Provider || auth.AuthKind() != coreauth.AuthKindOAuth {
		return nil
	}
	if _, explicitProbe := auth.Metadata["quota_probe"].(map[string]any); explicitProbe {
		return nil
	}
	return auth
}

// oauthAccessToken reads only OAuth access-token fields, never the generic
// api_key, id_token or session fallbacks of tokenValueForAuth.
func oauthAccessToken(metadata map[string]any) string {
	pick := func(m map[string]any) string {
		for _, key := range []string{"access_token", "accessToken"} {
			if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
		return ""
	}
	if v := pick(metadata); v != "" {
		return v
	}
	if nested, ok := metadata["token"].(map[string]any); ok {
		return pick(nested)
	}
	return ""
}

// resolveQuotaCredential uses the dashboard's proxy resolution without passing
// OAuth requests through the plugin HTTP client's request-log capture.
func (h *Handler) resolveQuotaCredential(_ context.Context, req pluginapi.QuotaFetchRequest) (quotaprovider.Credential, error) {
	auth := h.builtinQuotaAuth(req)
	if auth == nil {
		return quotaprovider.Credential{}, errors.New("quota credential unavailable")
	}
	token := oauthAccessToken(auth.Metadata)
	if token == "" {
		return quotaprovider.Credential{}, errors.New("quota credential unavailable")
	}
	accountID, _ := auth.Metadata["account_id"].(string)
	h.mu.Lock()
	transport := h.apiCallTransport(auth, "")
	h.mu.Unlock()
	return quotaprovider.Credential{Token: token, AccountID: strings.TrimSpace(accountID), Transport: transport}, nil
}
