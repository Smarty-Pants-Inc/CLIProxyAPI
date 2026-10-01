package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestAPIKeyPolicyRejectsAuthlessPluginExecutors(t *testing.T) {
	const key = "synthetic-plugin-policy-client"
	digest := sha256.Sum256([]byte(key))
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{APIKeyPolicies: []internalconfig.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}}}})
	host := &handlerDirectExecutorRouteHost{}
	host.hasRouters = true
	host.route = func(context.Context, pluginapi.ModelRouteRequest) (pluginapi.ModelRouteResponse, bool) {
		return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetExecutor, Target: "direct-plugin"}, true
	}
	handler := NewBaseAPIHandlers(&internalconfig.SDKConfig{}, manager)
	handler.SetModelRouterHost(host)
	ctx := coreauth.WithClientAPIKey(context.Background(), key)
	body := []byte(`{"model":"policy-plugin-model"}`)
	_, _, err := handler.ExecuteWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
	if err == nil || err.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("plugin execute = %v", err)
	}
	_, _, err = handler.ExecuteCountWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
	if err == nil || err.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("plugin count = %v", err)
	}
	data, _, errs := handler.ExecuteStreamWithAuthManager(ctx, "openai", "policy-plugin-model", body, "")
	if data != nil {
		t.Fatal("restricted plugin stream started")
	}
	if err = <-errs; err == nil || err.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("plugin stream = %v", err)
	}
	if host.lastPluginID != "" {
		t.Fatal("restricted request reached an auth-less plugin executor")
	}
}
