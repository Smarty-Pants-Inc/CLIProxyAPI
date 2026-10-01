package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const policyTestHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestAPIKeyPoliciesConfig(t *testing.T) {
	payload := "api-key-policies:\n  - key-sha256: " + strings.ToUpper(policyTestHash) + "\n    allowed-auths: [\"claude-*.json\", \"verified@example.com\"]\n    allowed-providers: [Claude, codex]\n    allowed-models: ['claude-*', 'gpt-5*']\n    daily-token-cap: 1000\n"
	cfg, err := ParseConfigBytes([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.APIKeyPolicies) != 1 || cfg.APIKeyPolicies[0].KeySHA256 != policyTestHash || cfg.APIKeyPolicies[0].AllowedProviders[0] != "claude" {
		t.Fatalf("policy normalization = %#v", cfg.APIKeyPolicies)
	}
	clone := cfg.CloneForRuntime()
	clone.APIKeyPolicies[0].AllowedAuths[0] = "changed.json"
	(*clone.APIKeyPolicies[0].AllowedModels)[0] = "changed-model"
	*clone.APIKeyPolicies[0].DailyTokenCap = 1
	if (*cfg.APIKeyPolicies[0].AllowedModels)[0] != "claude-*" || *cfg.APIKeyPolicies[0].DailyTokenCap != 1000 {
		t.Fatal("runtime clone shares model/cap policy")
	}
	if cfg.APIKeyPolicies[0].AllowedAuths[0] != "claude-*.json" {
		t.Fatal("runtime policy clone shares allowlist")
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(payload), 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfigPreserveComments(file, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(file)
	if err != nil || len(loaded.APIKeyPolicies) != 1 || loaded.APIKeyPolicies[0].AllowedAuths[1] != "verified@example.com" {
		t.Fatalf("policy save/load = %v, %v", loaded, err)
	}
}

func TestAPIKeyPoliciesRejectMalformedConfig(t *testing.T) {
	for _, tc := range []struct{ name, payload string }{
		{"trailing-policy-document", "api-keys: [synthetic]\n---\napi-key-policies: [{key-sha256: " + policyTestHash + "}]"},
		{"trailing-malformed-document", "api-key-policies: [{key-sha256: " + policyTestHash + "}]\n---\ninvalid: ["},
		{"bad-model-glob", "api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-models: ['[']}]"},
		{"blank-model-glob", "api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-models: ['']}]"},
		{"bad-cap-negative", "api-key-policies: [{key-sha256: " + policyTestHash + ", daily-token-cap: -1}]"},
		{"bad-cap-type", "api-key-policies: [{key-sha256: " + policyTestHash + ", daily-token-cap: infinite}]"},
		{"bad-cap-overflow", "api-key-policies: [{key-sha256: " + policyTestHash + ", daily-token-cap: 9999999999999999999999}]"},
		{"bad-hash", "api-key-policies: [{key-sha256: not-a-hash, allowed-auths: ['*']}]"},
		{"bad-block-type", "api-key-policies: invalid"},
		{"bad-yaml", "api-key-policies: ["},
		{"bad-weight-with-policy", "claude-api-key: [{api-key: synthetic, weight: bad}]\napi-key-policies: [{key-sha256: " + policyTestHash + "}]"},
		{"bad-glob", "api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['[']}]"},
		{"blank-glob", "api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['']}]"},
		{"bad-provider", "api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['*'], allowed-providers: ['*']}]"},
		{"duplicate-hash", "api-key-policies: [{key-sha256: " + policyTestHash + "}, {key-sha256: " + policyTestHash + "}]"},
		{"unauthenticated-websocket", "ws-auth: false\napi-key-policies: [{key-sha256: " + policyTestHash + "}]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConfigBytes([]byte(tc.payload)); err == nil {
				t.Fatal("malformed policy accepted")
			}
			file := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(file, []byte(tc.payload), 0600); err != nil {
				t.Fatal(err)
			}
			for _, optional := range []bool{false, true} {
				if _, err := LoadConfigOptional(file, optional); err == nil {
					t.Fatalf("optional=%v: malformed policy silently discarded", optional)
				}
			}
		})
	}
}

func TestAPIKeyPoliciesEmptyAllowlistDeniesByConfiguration(t *testing.T) {
	cfg, err := ParseConfigBytes([]byte("api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: []}]"))
	if err != nil || len(cfg.APIKeyPolicies) != 1 || len(cfg.APIKeyPolicies[0].AllowedAuths) != 0 {
		t.Fatalf("empty deny-all policy = %v, %v", cfg, err)
	}
}
