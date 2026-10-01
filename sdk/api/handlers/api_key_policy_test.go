package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestAPIKeyPolicyRejectsAuthlessPluginExecutors(t *testing.T) {
	const key = "synthetic-plugin-policy-client"
	digest := sha256.Sum256([]byte(key))
	zero := int64(0)
	for _, capOnly := range []bool{false, true} {
		policy := internalconfig.APIKeyPolicy{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}
		if capOnly {
			policy.AllowedAuths = []string{"*"}
			policy.DailyTokenCap = &zero
		}
		policies := []internalconfig.APIKeyPolicy{policy}
		for _, nilManager := range []bool{false, true} {
			for _, mode := range []string{"execute", "count", "stream"} {
				t.Run(fmt.Sprintf("nil-manager=%v/cap-only=%v/%s", nilManager, capOnly, mode), func(t *testing.T) {
					var manager *coreauth.Manager
					if !nilManager {
						manager = coreauth.NewManager(nil, nil, nil)
						manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{APIKeyPolicies: policies}})
					}
					host := &handlerDirectExecutorRouteHost{}
					host.hasRouters = true
					host.route = func(context.Context, pluginapi.ModelRouteRequest) (pluginapi.ModelRouteResponse, bool) {
						return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetExecutor, Target: "direct-plugin"}, true
					}
					h := NewBaseAPIHandlers(&internalconfig.SDKConfig{}, manager)
					h.SetModelRouterHost(host)
					ctx := coreauth.WithClientAPIKeyPolicies(context.Background(), key, policies)
					body := []byte(`{"model":"policy-plugin-model"}`)
					switch mode {
					case "execute":
						_, _, err := h.ExecuteWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
						if err == nil || (err.StatusCode != http.StatusServiceUnavailable && err.StatusCode != http.StatusTooManyRequests) {
							t.Errorf("plugin execute = %v", err)
						}
					case "count":
						_, _, err := h.ExecuteCountWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
						if err == nil || (err.StatusCode != http.StatusServiceUnavailable && err.StatusCode != http.StatusTooManyRequests) {
							t.Errorf("plugin count = %v", err)
						}
					case "stream":
						data, _, errs := h.ExecuteStreamWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
						if data != nil {
							t.Error("restricted plugin stream started")
							for range data {
							}
						}
						err := <-errs
						if err == nil || (err.StatusCode != http.StatusServiceUnavailable && err.StatusCode != http.StatusTooManyRequests) {
							t.Errorf("plugin stream = %v", err)
						}
					}
					if host.lastPluginID != "" {
						t.Errorf("restricted request reached auth-less plugin %q", host.lastPluginID)
					}
				})
			}
		}
	}
}
