package management

import (
	"context"
	"errors"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/quotaprovider"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// resolveQuotaCredential reuses the dashboard's token and proxy resolution without
// passing OAuth requests through the plugin HTTP client's request-log capture.
func (h *Handler) resolveQuotaCredential(ctx context.Context, req pluginapi.QuotaFetchRequest) (quotaprovider.Credential, error) {
	auth := h.authByIndex(req.AuthIndex)
	if auth == nil || auth.ID != req.AuthID || auth.Provider != req.Provider {
		return quotaprovider.Credential{}, errors.New("quota credential unavailable")
	}
	token, err := h.resolveTokenForAuth(ctx, auth, "")
	if err != nil {
		return quotaprovider.Credential{}, errors.New("quota credential unavailable")
	}
	accountID, _ := auth.Metadata["account_id"].(string)
	h.mu.Lock()
	transport := h.apiCallTransport(auth, "")
	h.mu.Unlock()
	return quotaprovider.Credential{Token: token, AccountID: strings.TrimSpace(accountID), Transport: transport}, nil
}
