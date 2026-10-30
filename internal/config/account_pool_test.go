package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func accountPoolEntry(id, org, class, maxInFlight, accounts string) string {
	entry := fmt.Sprintf("  - id: %s\n    org: %s\n    class: %s\n", id, org, class)
	if maxInFlight != "" {
		entry += "    max-in-flight: " + maxInFlight + "\n"
	}
	if accounts == "[]" {
		return entry + "    accounts: []\n"
	}
	return entry + "    accounts:\n" + accounts
}

func poolAccountEntry(provider, accountID, entitlementID string) string {
	return fmt.Sprintf("      - provider: %s\n        account-id: %s\n        entitlement-id: %s\n", provider, accountID, entitlementID)
}

func poolPolicyEntry(key, pool string, fields ...string) string {
	entry := fmt.Sprintf("  - key-sha256: %s\n    pool: %s\n", APIKeyDigest(key), pool)
	for _, field := range fields {
		entry += "    " + field + "\n"
	}
	return entry
}

func accountPoolConfig(v8 bool, keys []string, pools, policies, suffix string) string {
	keyList := "[" + strings.Join(keys, ", ") + "]"
	var out strings.Builder
	if v8 {
		fmt.Fprintf(&out, "access:\n  api-keys: %s\n", keyList)
		writePoolConfigBlock(&out, 2, "account-pools", pools)
		writePoolConfigBlock(&out, 2, "api-key-policies", policies)
		out.WriteString("oauth:\n  providers:\n    aistudio:\n      ws-auth: true\n    codex:\n      live-media-relay:\n        enabled: true\n")
	} else {
		fmt.Fprintf(&out, "api-keys: %s\nws-auth: true\ncodex:\n  live-media-relay:\n    enabled: true\n", keyList)
		writePoolConfigBlock(&out, 0, "account-pools", pools)
		writePoolConfigBlock(&out, 0, "api-key-policies", policies)
	}
	out.WriteString(suffix)
	return out.String()
}

func writePoolConfigBlock(out *strings.Builder, indent int, key, value string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "[]" || trimmed == "null" {
		fmt.Fprintf(out, "%s%s: %s\n", strings.Repeat(" ", indent), key, trimmed)
		return
	}
	fmt.Fprintf(out, "%s%s:\n", strings.Repeat(" ", indent), key)
	for _, line := range strings.Split(strings.TrimSuffix(value, "\n"), "\n") {
		fmt.Fprintf(out, "%s%s\n", strings.Repeat(" ", indent), line)
	}
}

func yamlNodeAtPath(data []byte, path ...string) (*yaml.Node, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, fmt.Errorf("unexpected YAML document shape")
	}
	node := document.Content[0]
	for _, key := range path {
		if node.Kind != yaml.MappingNode {
			return nil, nil
		}
		found := false
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				node = node.Content[i+1]
				found = true
				break
			}
		}
		if !found {
			return nil, nil
		}
	}
	return node, nil
}

func assertConfigEntryPointsReject(t *testing.T, raw string) {
	t.Helper()
	if _, err := ParseConfigBytes([]byte(raw)); err == nil {
		t.Fatal("ParseConfigBytes accepted invalid account-pools configuration")
	}
	if _, err := LoadConfigBytes([]byte(raw), filepath.Join(t.TempDir(), "config.yaml"), false); err == nil {
		t.Fatal("LoadConfigBytes accepted invalid account-pools configuration")
	}
	var cfg Config
	if err := yaml.Unmarshal([]byte(raw), &cfg); err == nil {
		t.Fatal("direct Config YAML decode accepted invalid account-pools configuration")
	}
}

func TestAccountPoolsAbsentKeepsLegacyPolicySemantics(t *testing.T) {
	key := "legacy-client"
	raw := fmt.Sprintf(`api-keys: [%s]
ws-auth: true
api-key-policies:
  - key-sha256: %s
    allowed-auths: []
    daily-token-cap: 0
    daily-request-cap: 0
`, key, APIKeyDigest(key))

	cfg, err := ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatalf("legacy config rejected: %v", err)
	}
	if len(cfg.APIKeyPolicies) != 1 || len(cfg.APIKeyPolicies[0].AllowedAuths) != 0 {
		t.Fatalf("legacy policy changed: %+v", cfg.APIKeyPolicies)
	}
	policy := cfg.APIKeyPolicies[0]
	if policy.DailyTokenCap == nil || *policy.DailyTokenCap != 0 || policy.DailyRequestCap == nil || *policy.DailyRequestCap != 0 {
		t.Fatalf("legacy daily caps changed: %+v", policy)
	}
	if _, err := LoadConfigBytes([]byte(raw), filepath.Join(t.TempDir(), "config.yaml"), false); err != nil {
		t.Fatalf("legacy LoadConfigBytes rejected: %v", err)
	}
}

func TestAccountPoolsExplicitNullRejectedBeforePointerCollapse(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "flat", raw: "account-pools: null\n"},
		{name: "v8", raw: "access:\n  account-pools: null\n"},
		{name: "yaml alias", raw: "pool-null: &pool-null null\naccount-pools: *pool-null\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertConfigEntryPointsReject(t, tc.raw)
		})
	}
}

func TestAccountPoolsV8LayoutDecodesAndValidates(t *testing.T) {
	key := "v8-client"
	account := poolAccountEntry("codex", "v8-account", "v8-entitlement")
	raw := accountPoolConfig(true, []string{key},
		accountPoolEntry("v8-pool", "v8-org", "human", "1", account),
		poolPolicyEntry(key, "v8-pool"), "")

	cfg, err := ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatalf("valid v8 pool config rejected: %v", err)
	}
	if len(cfg.APIKeys) != 1 || cfg.APIKeys[0] != key || len(cfg.APIKeyPolicies) != 1 {
		t.Fatalf("v8 access section was not decoded: keys=%v policies=%d", cfg.APIKeys, len(cfg.APIKeyPolicies))
	}
}

func TestAccountPoolsEmptyModeIsNotLegacyFallback(t *testing.T) {
	key := "empty-client"
	for _, v8 := range []bool{false, true} {
		t.Run(fmt.Sprintf("with keys/v8=%t", v8), func(t *testing.T) {
			raw := accountPoolConfig(v8, []string{key}, "[]", poolPolicyEntry(key, "missing"), "")
			if _, err := ParseConfigBytes([]byte(raw)); err == nil {
				t.Fatal("present empty account-pools with configured keys fell back to legacy mode")
			}
		})
	}

	for _, v8 := range []bool{false, true} {
		t.Run(fmt.Sprintf("without keys/v8=%t", v8), func(t *testing.T) {
			raw := accountPoolConfig(v8, nil, "[]", "[]", "")
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfigBytes([]byte(raw), path, false)
			if err != nil {
				t.Fatalf("empty enabled pool mode rejected without keys: %v", err)
			}
			if err := SaveConfigPreserveComments(path, cfg); err != nil {
				t.Fatalf("empty enabled pool mode was not serializable: %v", err)
			}
			serialized, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			poolPath := []string{"account-pools"}
			if v8 {
				poolPath = []string{"access", "account-pools"}
			}
			node, err := yamlNodeAtPath(serialized, poolPath...)
			if err != nil {
				t.Fatal(err)
			}
			if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) != 0 {
				t.Fatalf("explicit empty pool mode was lost on save: %s", serialized)
			}
			if legacy, err := yamlNodeAtPath(serialized, "api-key-policies"); err != nil {
				t.Fatal(err)
			} else if legacy != nil {
				t.Fatalf("empty pool mode gained legacy policies: %s", serialized)
			}
		})
	}
}

func TestAccountPoolsValidationBoundaries(t *testing.T) {
	accountOne := poolAccountEntry("codex", "account-one", "entitlement-one")
	accountTwo := poolAccountEntry("claude", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
	validPools := accountPoolEntry("human-pool", "org-one", "human", "0", accountOne) +
		accountPoolEntry("agent-pool", "org-two", "agent", "2", accountTwo)
	validPolicies := poolPolicyEntry("human-client", "human-pool", "allowed-models: []") +
		poolPolicyEntry("agent-client", "agent-pool")

	cases := []struct {
		name        string
		keys        []string
		pools       string
		policies    string
		wantError   bool
		wantMessage string
	}{
		{
			name:     "valid human and agent codex and claude pools",
			keys:     []string{"human-client", "agent-client"},
			pools:    validPools,
			policies: validPolicies,
		},
		{
			name:     "same account repeated inside one pool",
			keys:     []string{"same-pool-client"},
			pools:    accountPoolEntry("one-pool", "org-one", "human", "1", accountOne+accountOne),
			policies: poolPolicyEntry("same-pool-client", "one-pool"),
		},
		{
			name:        "invalid class",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "robot", "1", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool"),
			wantError:   true,
			wantMessage: "class",
		},
		{
			name:        "duplicate pool id",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org-one", "human", "1", accountOne) + accountPoolEntry("pool", "org-two", "agent", "1", accountTwo),
			policies:    poolPolicyEntry("pool-client", "pool"),
			wantError:   true,
			wantMessage: "id",
		},
		{
			name:        "duplicate org and class",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool-one", "org-one", "human", "1", accountOne) + accountPoolEntry("pool-two", "org-one", "human", "1", accountTwo),
			policies:    poolPolicyEntry("pool-client", "pool-one"),
			wantError:   true,
			wantMessage: "org",
		},
		{
			name:        "unknown pool reference",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:    poolPolicyEntry("pool-client", "missing"),
			wantError:   true,
			wantMessage: "pool",
		},
		{
			name:      "missing key coverage",
			keys:      []string{"pool-client", "uncovered-client"},
			pools:     accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:  poolPolicyEntry("pool-client", "pool"),
			wantError: true,
		},
		{
			name:      "unconfigured policy key",
			keys:      []string{"pool-client"},
			pools:     accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:  poolPolicyEntry("other-client", "pool"),
			wantError: true,
		},
		{
			name:        "missing max in flight",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool"),
			wantError:   true,
			wantMessage: "max-in-flight",
		},
		{
			name:        "negative max in flight",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "-1", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool"),
			wantError:   true,
			wantMessage: "max-in-flight",
		},
		{
			name:        "unsupported provider",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "1", poolAccountEntry("gemini", "account-one", "entitlement-one")),
			policies:    poolPolicyEntry("pool-client", "pool"),
			wantError:   true,
			wantMessage: "provider",
		},
		{
			name: "account overlap across different orgs",
			keys: []string{"one-client", "two-client"},
			pools: accountPoolEntry("one", "org-one", "human", "1", poolAccountEntry("codex", "shared-account", "entitlement-one")) +
				accountPoolEntry("two", "org-two", "agent", "1", poolAccountEntry("codex", "shared-account", "entitlement-two")),
			policies:    poolPolicyEntry("one-client", "one") + poolPolicyEntry("two-client", "two"),
			wantError:   true,
			wantMessage: "account",
		},
		{
			name: "entitlement overlap across different orgs",
			keys: []string{"one-client", "two-client"},
			pools: accountPoolEntry("one", "org-one", "human", "1", poolAccountEntry("codex", "account-one", "shared-entitlement")) +
				accountPoolEntry("two", "org-two", "agent", "1", poolAccountEntry("codex", "account-two", "shared-entitlement")),
			policies:    poolPolicyEntry("one-client", "one") + poolPolicyEntry("two-client", "two"),
			wantError:   true,
			wantMessage: "entitlement",
		},
		{
			name:        "pooled allowed auths empty is rejected",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool", "allowed-auths: []"),
			wantError:   true,
			wantMessage: "allowed-auths",
		},
		{
			name:        "pooled daily token cap zero is rejected",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool", "daily-token-cap: 0"),
			wantError:   true,
			wantMessage: "daily-token-cap",
		},
		{
			name:        "pooled daily request cap zero is rejected",
			keys:        []string{"pool-client"},
			pools:       accountPoolEntry("pool", "org", "human", "1", accountOne),
			policies:    poolPolicyEntry("pool-client", "pool", "daily-request-cap: 0"),
			wantError:   true,
			wantMessage: "daily-request-cap",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := accountPoolConfig(false, tc.keys, tc.pools, tc.policies, "")
			_, err := ParseConfigBytes([]byte(raw))
			if tc.wantError {
				if err == nil {
					t.Fatal("invalid account-pools configuration was accepted")
				}
				if tc.wantMessage != "" && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantMessage)) {
					t.Fatalf("error %q does not name %q", err, tc.wantMessage)
				}
				return
			}
			if err != nil {
				t.Fatalf("valid account-pools configuration rejected: %v", err)
			}
		})
	}
}

func TestAccountPoolsRejectHomePluginsAndUnauthenticatedWebsocket(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*Config)
		want string
	}{
		{name: "Home", set: func(cfg *Config) { cfg.Home.Enabled = true }, want: "home"},
		{name: "plugins", set: func(cfg *Config) { cfg.Plugins.Enabled = true }, want: "plugin"},
		{name: "ws auth", set: func(cfg *Config) { cfg.WebsocketAuth = false }, want: "ws-auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte("account-pools: []\n"))
			if err != nil {
				t.Fatalf("empty enabled pool mode rejected before compatibility check: %v", err)
			}
			tc.set(cfg)
			if err := cfg.ValidateAPIKeyPolicies(); err == nil {
				t.Fatal("incompatible runtime configuration was accepted")
			} else if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("error %q does not name %q", err, tc.want)
			}
		})
	}
}
