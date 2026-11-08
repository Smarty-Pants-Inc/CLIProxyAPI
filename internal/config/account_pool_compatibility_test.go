package config

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Keep these real YAML entry-point checks for the partial-snapshot regression
// reported by Main and the new pool configuration's validation boundary.
func TestConfigDirectLegacyPolicySnapshotCompatibility(t *testing.T) {
	key := "legacy-snapshot-client"
	digest := APIKeyDigest(key)
	policy := fmt.Sprintf("api-key-policies:\n  - key-sha256: %s\n    allowed-auths: []\n    daily-token-cap: 0\n", digest)
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "without websocket default", raw: "api-keys: [" + key + "]\n" + policy},
		{name: "without keys or websocket default", raw: policy},
		{name: "explicit websocket false", raw: "api-keys: [" + key + "]\nws-auth: false\n" + policy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			if err := yaml.Unmarshal([]byte(tc.raw), &cfg); err != nil {
				t.Fatalf("legacy partial snapshot must decode without full policy validation: %v", err)
			}
			if cfg.WebsocketAuth || cfg.AccountPools != nil || len(cfg.APIKeyPolicies) != 1 || cfg.APIKeyPolicies[0].KeySHA256 != digest {
				t.Fatalf("legacy partial snapshot changed: %+v", cfg.SDKConfig)
			}
			if err := cfg.ValidateAPIKeyPolicies(); err == nil {
				t.Fatal("explicit full policy validation accepted the partial snapshot")
			}
		})
	}

	// Parse/Load still supply the websocket default before full validation.
	raw := []byte("api-keys: [" + key + "]\n" + policy)
	parsed, err := ParseConfigBytes(raw)
	if err != nil || !parsed.WebsocketAuth {
		t.Fatalf("ParseConfigBytes no longer supplies the legacy websocket default: cfg=%+v err=%v", parsed, err)
	}
	loaded, err := LoadConfigBytes(raw, filepath.Join(t.TempDir(), "config.yaml"), false)
	if err != nil || !loaded.WebsocketAuth {
		t.Fatalf("LoadConfigBytes no longer supplies the legacy websocket default: cfg=%+v err=%v", loaded, err)
	}
	for _, invalid := range []string{policy, "api-keys: [" + key + "]\nws-auth: false\n" + policy} {
		assertConfigEntryPointsRejectFullPolicy(t, invalid)
	}
}

func assertConfigEntryPointsRejectFullPolicy(t *testing.T, raw string) {
	t.Helper()
	if _, err := ParseConfigBytes([]byte(raw)); err == nil {
		t.Fatal("ParseConfigBytes skipped full policy validation")
	}
	if _, err := LoadConfigBytes([]byte(raw), filepath.Join(t.TempDir(), "config.yaml"), false); err == nil {
		t.Fatal("LoadConfigBytes skipped full policy validation")
	}
}

func TestConfigDirectPooledPolicyValidationRemainsStrict(t *testing.T) {
	key := "pool-snapshot-client"
	pool := accountPoolEntry("pool", "org", "agent", "0", "[]")
	for _, v8 := range []bool{false, true} {
		for _, tc := range []struct {
			name     string
			pools    string
			policies string
		}{
			{name: "null", pools: "null", policies: "[]"},
			{name: "empty with configured keys", pools: "[]", policies: "[]"},
			{name: "missing coverage", pools: pool, policies: "[]"},
			{name: "invalid pool", pools: accountPoolEntry("pool", "org", "robot", "0", "[]"), policies: poolPolicyEntry(key, "pool")},
		} {
			t.Run(fmt.Sprintf("%s/v8=%t", tc.name, v8), func(t *testing.T) {
				assertConfigEntryPointsReject(t, accountPoolConfig(v8, []string{key}, tc.pools, tc.policies, ""))
			})
		}
	}
	for _, raw := range []string{
		"api-keys: [" + key + "]\nws-auth: true\napi-key-policies:\n" + poolPolicyEntry(key, "pool"),
		"access:\n  api-keys: [" + key + "]\n  api-key-policies:\n  " + strings.ReplaceAll(strings.TrimSuffix(poolPolicyEntry(key, "pool"), "\n"), "\n", "\n  ") + "\n",
	} {
		assertConfigEntryPointsReject(t, raw)
	}
}

func TestAPIKeyPolicyDigestValidationCompatibility(t *testing.T) {
	key := "digest-client"
	digest := APIKeyDigest(key)
	for _, tc := range []struct {
		name   string
		digest string
	}{
		{name: "invalid hex", digest: strings.Repeat("z", 64)},
		{name: "uppercase", digest: strings.ToUpper(digest)},
		{name: "short", digest: digest[:62]},
		{name: "long", digest: digest + "00"},
		{name: "unconfigured", digest: APIKeyDigest("unconfigured-client")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Sprintf("api-keys: [%s]\napi-key-policies:\n  - key-sha256: %s\n", key, tc.digest)
			assertConfigEntryPointsRejectFullPolicy(t, raw)
		})
	}
	for _, suffix := range []string{
		"    daily-token-cap: -1\n",
		"    daily-request-cap: -1\n",
		"  - key-sha256: " + digest + "\n",
	} {
		raw := fmt.Sprintf("api-keys: [%s]\napi-key-policies:\n  - key-sha256: %s\n%s", key, digest, suffix)
		assertConfigEntryPointsRejectFullPolicy(t, raw)
	}
	if _, err := ParseConfigBytes([]byte(fmt.Sprintf("api-keys: [' %s ']\napi-key-policies:\n  - key-sha256: %s\n", key, digest))); err != nil {
		t.Fatalf("normalized legacy key digest rejected: %v", err)
	}
}
