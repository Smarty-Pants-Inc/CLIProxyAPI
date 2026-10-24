package config_test

import (
	"fmt"
	"testing"

	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func TestSDKConfigDirectLegacyPartialPolicySnapshotsRemainCompatible(t *testing.T) {
	key := "sdk-partial-client"
	policy := fmt.Sprintf("api-key-policies:\n  - key-sha256: %s\n    daily-token-cap: 0\n", sdkKeyDigest(key))
	for _, raw := range []string{policy, "api-keys: [" + key + "]\n" + policy} {
		var cfg sdkconfig.SDKConfig
		if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
			t.Fatalf("legacy standalone SDK partial policy snapshot rejected: %v", err)
		}
		if cfg.AccountPools != nil || len(cfg.APIKeyPolicies) != 1 || cfg.APIKeyPolicies[0].DailyTokenCap == nil || *cfg.APIKeyPolicies[0].DailyTokenCap != 0 {
			t.Fatalf("legacy standalone SDK policy snapshot changed: %+v", cfg)
		}
	}
}

func TestSDKConfigDirectPooledPolicyValidationRemainsStrict(t *testing.T) {
	key := "sdk-validation-client"
	pool := sdkPoolYAML("codex", "sdk-account", "sdk-entitlement")
	for _, raw := range []string{
		fmt.Sprintf("api-keys: [%s]\napi-key-policies:\n  - key-sha256: %s\n    pool: sdk-pool\n", key, sdkKeyDigest(key)),
		sdkConfigYAML([]string{key}, pool, "  []\n"),
		"access:\n  account-pools: null\n",
		"access:\n  api-keys: [" + key + "]\n  account-pools: []\n",
	} {
		var cfg sdkconfig.SDKConfig
		if err := yaml.Unmarshal([]byte(raw), &cfg); err == nil {
			t.Fatalf("standalone SDK accepted invalid pooled policy snapshot: %s", raw)
		}
	}
}
