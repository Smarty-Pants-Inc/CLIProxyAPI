package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"gopkg.in/yaml.v3"
)

func sdkKeyDigest(key string) string {
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:])
}

func sdkPoolYAML(provider, accountID, entitlementID string) string {
	return fmt.Sprintf(`- id: sdk-pool
  org: sdk-org
  class: human
  max-in-flight: 1
  accounts:
    - provider: %s
      account-id: %s
      entitlement-id: %s
`, provider, accountID, entitlementID)
}

func sdkConfigYAML(keys []string, pools, policies string) string {
	return fmt.Sprintf(`api-keys: [%s]
ws-auth: true
account-pools:
%sapi-key-policies:
%s`, strings.Join(keys, ", "), pools, policies)
}

func sdkNodeAt(data []byte, key string) (*yaml.Node, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("unexpected YAML document shape")
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			return root.Content[i+1], nil
		}
	}
	return nil, nil
}

func TestSDKConfigAccountPoolsAbsentKeepsLegacyPolicySemantics(t *testing.T) {
	key := "sdk-legacy-client"
	raw := fmt.Sprintf(`api-keys: [%s]
ws-auth: true
api-key-policies:
  - key-sha256: %s
    allowed-auths: []
    daily-token-cap: 0
    daily-request-cap: 0
`, key, sdkKeyDigest(key))

	var cfg sdkconfig.SDKConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("legacy SDKConfig rejected: %v", err)
	}
	if len(cfg.APIKeys) != 1 || len(cfg.APIKeyPolicies) != 1 {
		t.Fatalf("legacy SDKConfig policy changed: keys=%v policies=%d", cfg.APIKeys, len(cfg.APIKeyPolicies))
	}
	policy := cfg.APIKeyPolicies[0]
	if policy.DailyTokenCap == nil || *policy.DailyTokenCap != 0 || policy.DailyRequestCap == nil || *policy.DailyRequestCap != 0 {
		t.Fatalf("legacy daily caps changed: %+v", policy)
	}
}

func TestSDKConfigExplicitNullAccountPoolsRejected(t *testing.T) {
	for _, raw := range []string{
		"account-pools: null\n",
		"pool-null: &pool-null null\naccount-pools: *pool-null\n",
	} {
		var cfg sdkconfig.SDKConfig
		if err := yaml.Unmarshal([]byte(raw), &cfg); err == nil {
			t.Fatalf("standalone SDKConfig accepted explicit null account-pools in %q", raw)
		}
	}
}

func TestSDKConfigEmptyAccountPoolsWithKeysRejected(t *testing.T) {
	key := "sdk-empty-client"
	raw := sdkConfigYAML([]string{key}, "  []\n", fmt.Sprintf("  - key-sha256: %s\n    pool: sdk-pool\n", sdkKeyDigest(key)))
	var cfg sdkconfig.SDKConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err == nil {
		t.Fatal("standalone SDKConfig treated explicit empty account-pools with keys as legacy")
	}
}

func TestSDKConfigEmptyAccountPoolsWithoutKeysRemainEnabledOnSerialize(t *testing.T) {
	raw := "account-pools: []\n"
	var cfg sdkconfig.SDKConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("empty enabled SDKConfig rejected without keys: %v", err)
	}
	serialized, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	node, err := sdkNodeAt(serialized, "account-pools")
	if err != nil {
		t.Fatal(err)
	}
	if node == nil || node.Kind != yaml.SequenceNode || len(node.Content) != 0 {
		t.Fatalf("explicit empty account-pools was lost on SDK serialization: %s", serialized)
	}
	if policies, err := sdkNodeAt(serialized, "api-key-policies"); err != nil {
		t.Fatal(err)
	} else if policies != nil {
		t.Fatalf("empty pool mode gained legacy policies: %s", serialized)
	}
}

func TestSDKConfigValidAccountPoolAndPolicySurviveStandaloneDecode(t *testing.T) {
	key := "sdk-pool-client"
	pool := sdkPoolYAML("claude", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444")
	policy := fmt.Sprintf("  - key-sha256: %s\n    pool: sdk-pool\n", sdkKeyDigest(key))
	raw := sdkConfigYAML([]string{key}, pool, policy)

	var cfg sdkconfig.SDKConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("valid standalone SDKConfig rejected: %v", err)
	}
	serialized, err := yaml.Marshal(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	poolNode, err := sdkNodeAt(serialized, "account-pools")
	if err != nil {
		t.Fatal(err)
	}
	if poolNode == nil || poolNode.Kind != yaml.SequenceNode || len(poolNode.Content) != 1 {
		t.Fatalf("account-pools was ignored by standalone SDKConfig: %s", serialized)
	}
	policyNode, err := sdkNodeAt(serialized, "api-key-policies")
	if err != nil {
		t.Fatal(err)
	}
	if policyNode == nil || policyNode.Kind != yaml.SequenceNode || len(policyNode.Content) != 1 {
		t.Fatalf("api-key-policies was not serialized: %s", serialized)
	}
	foundPool := false
	for i := 0; i+1 < len(policyNode.Content[0].Content); i += 2 {
		if policyNode.Content[0].Content[i].Value == "pool" && policyNode.Content[0].Content[i+1].Value == "sdk-pool" {
			foundPool = true
			break
		}
	}
	if !foundPool {
		t.Fatalf("pool reference was lost by standalone SDKConfig serialization: %s", serialized)
	}
}
