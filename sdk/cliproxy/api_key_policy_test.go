package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"testing"
)

func TestAPIKeyPolicyHomePreservesAuthenticationAndOverlayFloor(t *testing.T) {
	policy := config.APIKeyPolicy{KeySHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AllowedAuths: []string{"verified.json"}}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"synthetic-client"}, APIKeyPolicies: []config.APIKeyPolicy{policy}}}
	cfg.Home.Enabled = true
	forceHomeRuntimeConfig(cfg)
	if len(cfg.APIKeys) != 1 || !cfg.WebsocketAuth {
		t.Fatal("Home stripped client authentication with allowlists")
	}
	mergedConfig := &config.Config{}
	mergeHomeClientSecurity(cfg, mergedConfig)
	forceHomeRuntimeConfig(mergedConfig)
	if len(mergedConfig.APIKeyPolicies) != 1 || len(mergedConfig.APIKeys) != 1 || !mergedConfig.WebsocketAuth {
		t.Fatal("Home overlay discarded local credential boundary")
	}
	narrowed := config.APIKeyPolicy{KeySHA256: policy.KeySHA256, AllowedAuths: []string{"other.json"}}
	merged := mergeHomeAPIKeyPolicies(cfg.APIKeyPolicies, []config.APIKeyPolicy{narrowed})
	if len(merged) != 2 {
		t.Fatal("remote policy did not intersect local floor")
	}
	if len(mergeHomeAPIKeyPolicies(merged, []config.APIKeyPolicy{narrowed})) != 2 {
		t.Fatal("unchanged overlays grow policy state")
	}
	legacy := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"synthetic-client"}}}
	forceHomeRuntimeConfig(legacy)
	if len(legacy.APIKeys) != 0 || legacy.WebsocketAuth {
		t.Fatal("unpolicied Home behavior changed")
	}
}
