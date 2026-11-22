package config

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// PoolClass identifies the client class assigned to an account pool.
type PoolClass string

const (
	PoolClassHuman PoolClass = "human"
	PoolClassAgent PoolClass = "agent"
)

// PoolAccount identifies one provider account and its shared entitlement.
type PoolAccount struct {
	Provider      string `yaml:"provider" json:"provider"`
	AccountID     string `yaml:"account-id" json:"account-id"`
	EntitlementID string `yaml:"entitlement-id" json:"entitlement-id"`
}

// AccountPool reserves a set of provider accounts for one client class and organization.
type AccountPool struct {
	ID          string        `yaml:"id" json:"id"`
	Org         string        `yaml:"org" json:"org"`
	Class       PoolClass     `yaml:"class" json:"class"`
	MaxInFlight *int64        `yaml:"max-in-flight" json:"max-in-flight"`
	Accounts    []PoolAccount `yaml:"accounts" json:"accounts"`
}

var accountPoolNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// UnmarshalYAML validates standalone SDK snapshots before pointer decoding can
// erase whether account-pools was explicitly null.
func (cfg *SDKConfig) UnmarshalYAML(node *yaml.Node) error {
	if cfg == nil {
		return nil
	}
	if err := validateAccountPoolsNode(node); err != nil {
		return err
	}

	decodeNode := sdkConfigDecodeNode(node)
	type plain SDKConfig
	decoded := plain(*cfg)
	if err := decodeNode.Decode(&decoded); err != nil {
		return err
	}
	if decoded.AccountPools != nil || hasPooledAPIKeyPolicy(decoded.APIKeyPolicies) {
		if err := validateAccountPoolConfiguration(decoded.AccountPools, decoded.APIKeys, decoded.APIKeyPolicies); err != nil {
			return err
		}
	}
	*cfg = SDKConfig(decoded)
	return nil
}

func sdkConfigDecodeNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return node
	}
	root := expandConfigAliases(node)
	if root == nil || root.Kind != yaml.MappingNode {
		return root
	}

	// Standalone SDK snapshots may use the v8 access wrapper. Project the SDK
	// fields into their legacy decode names without interpreting server fields.
	if value := yamlPath(root, "access.account-pools"); value != nil {
		copy := deepCopyNode(root)
		setYAMLPath(copy, "account-pools", deepCopyNode(value))
		if keys := yamlPath(root, "access.api-keys"); keys != nil && keys.Kind == yaml.SequenceNode {
			setYAMLPath(copy, "api-keys", deepCopyNode(keys))
		}
		if policies := yamlPath(root, "access.api-key-policies"); policies != nil && policies.Kind == yaml.SequenceNode {
			setYAMLPath(copy, "api-key-policies", deepCopyNode(policies))
		}
		return copy
	}
	return root
}

func validateAccountPoolsNode(node *yaml.Node) error {
	value := accountPoolsNode(node)
	if value == nil {
		return nil
	}
	if value.Tag == "!!null" {
		return fmt.Errorf("account-pools must be omitted or a list, not null")
	}
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("account-pools must be a list")
	}
	return nil
}

func accountPoolsNode(node *yaml.Node) *yaml.Node {
	if node == nil {
		return nil
	}
	root := expandConfigAliases(node)
	if root == nil {
		return nil
	}
	if value := yamlPath(root, "access.account-pools"); value != nil {
		return value
	}
	return yamlPath(root, "account-pools")
}

func hasPooledAPIKeyPolicy(policies []APIKeyPolicy) bool {
	for _, policy := range policies {
		if policy.Pool != "" {
			return true
		}
	}
	return false
}

func validateAccountPoolConfiguration(accountPools *[]AccountPool, apiKeys []string, policies []APIKeyPolicy) error {
	if accountPools == nil {
		for index := range policies {
			if policies[index].Pool != "" {
				return fmt.Errorf("api-key-policy pool requires account-pools")
			}
		}
		return validateLegacyAPIKeyPolicies(apiKeys, policies)
	}

	if len(*accountPools) > 0 {
		if err := validateAccountPools(*accountPools); err != nil {
			return err
		}
	}
	if len(*accountPools) == 0 && len(apiKeys) > 0 {
		return fmt.Errorf("account-pools must contain at least one pool when api-keys are configured")
	}

	configured := make(map[string]bool, len(apiKeys))
	for _, key := range apiKeys {
		configured[APIKeyDigest(key)] = true
	}
	pools := make(map[string]bool, len(*accountPools))
	for _, pool := range *accountPools {
		pools[pool.ID] = true
	}
	seen := make(map[string]bool, len(policies))
	for index := range policies {
		policy := &policies[index]
		if err := validateAPIKeyPolicyKey(policy, configured, seen); err != nil {
			return err
		}
		if policy.Pool == "" {
			return fmt.Errorf("api-key-policy for %s must name pool", policy.KeySHA256)
		}
		if !pools[policy.Pool] {
			return fmt.Errorf("api-key-policy for %s references unknown pool %q", policy.KeySHA256, policy.Pool)
		}
		if policy.AllowedAuths != nil {
			return fmt.Errorf("api-key-policy allowed-auths is unsupported in pool mode")
		}
		if policy.DailyTokenCap != nil {
			return fmt.Errorf("api-key-policy daily-token-cap is unsupported in pool mode")
		}
		if policy.DailyRequestCap != nil {
			return fmt.Errorf("api-key-policy daily-request-cap is unsupported in pool mode")
		}
	}
	for _, key := range apiKeys {
		digest := APIKeyDigest(key)
		if !seen[digest] {
			return fmt.Errorf("api-key %s has no account-pool policy", digest)
		}
	}
	return nil
}

func validateLegacyAPIKeyPolicies(apiKeys []string, policies []APIKeyPolicy) error {
	configured := make(map[string]bool, len(apiKeys))
	for _, key := range apiKeys {
		configured[APIKeyDigest(key)] = true
	}
	seen := make(map[string]bool, len(policies))
	for index := range policies {
		if err := validateAPIKeyPolicyKey(&policies[index], configured, seen); err != nil {
			return err
		}
		for _, cap := range []*int64{policies[index].DailyTokenCap, policies[index].DailyRequestCap} {
			if cap != nil && *cap < 0 {
				return fmt.Errorf("api-key-policy caps must be nonnegative")
			}
		}
	}
	return nil
}

func validateAPIKeyPolicyKey(policy *APIKeyPolicy, configured map[string]bool, seen map[string]bool) error {
	if policy == nil {
		return fmt.Errorf("nil api-key-policy")
	}
	if len(policy.KeySHA256) != 64 || strings.ToLower(policy.KeySHA256) != policy.KeySHA256 {
		return fmt.Errorf("invalid, unconfigured or duplicate api-key-policy key-sha256")
	}
	if digest, err := hex.DecodeString(policy.KeySHA256); err != nil || len(digest) != 32 || !configured[policy.KeySHA256] || seen[policy.KeySHA256] {
		return fmt.Errorf("invalid, unconfigured or duplicate api-key-policy key-sha256")
	}
	seen[policy.KeySHA256] = true
	return nil
}

func validateAccountPools(pools []AccountPool) error {
	poolIDs := make(map[string]bool, len(pools))
	orgClasses := make(map[string]bool, len(pools))
	accountAtoms := make(map[string]int, len(pools))
	for poolIndex := range pools {
		pool := &pools[poolIndex]
		if !accountPoolNamePattern.MatchString(pool.ID) {
			return fmt.Errorf("account-pools[%d].id must match [a-z0-9][a-z0-9._-]{0,63}", poolIndex)
		}
		if poolIDs[pool.ID] {
			return fmt.Errorf("account-pools[%d].id %q is duplicated", poolIndex, pool.ID)
		}
		poolIDs[pool.ID] = true
		if !accountPoolNamePattern.MatchString(pool.Org) {
			return fmt.Errorf("account-pools[%d].org must match [a-z0-9][a-z0-9._-]{0,63}", poolIndex)
		}
		if pool.Class != PoolClassHuman && pool.Class != PoolClassAgent {
			return fmt.Errorf("account-pools[%d].class must be human or agent", poolIndex)
		}
		orgClass := pool.Org + "\x00" + string(pool.Class)
		if orgClasses[orgClass] {
			return fmt.Errorf("account-pools[%d].org and class combination is duplicated", poolIndex)
		}
		orgClasses[orgClass] = true
		if pool.MaxInFlight == nil {
			return fmt.Errorf("account-pools[%d].max-in-flight is required", poolIndex)
		}
		if *pool.MaxInFlight < 0 {
			return fmt.Errorf("account-pools[%d].max-in-flight must be nonnegative", poolIndex)
		}

		for accountIndex := range pool.Accounts {
			account := &pool.Accounts[accountIndex]
			if account.Provider != "codex" && account.Provider != "claude" {
				return fmt.Errorf("account-pools[%d].accounts[%d].provider must be codex or claude", poolIndex, accountIndex)
			}
			if account.Provider == "claude" {
				var err error
				account.AccountID, err = normalizePoolUUID(account.AccountID)
				if err != nil {
					return fmt.Errorf("account-pools[%d].accounts[%d].account-id must be a Claude UUID: %w", poolIndex, accountIndex, err)
				}
				account.EntitlementID, err = normalizePoolUUID(account.EntitlementID)
				if err != nil {
					return fmt.Errorf("account-pools[%d].accounts[%d].entitlement-id must be a Claude UUID: %w", poolIndex, accountIndex, err)
				}
			} else {
				if err := validateOpaquePoolID(account.AccountID); err != nil {
					return fmt.Errorf("account-pools[%d].accounts[%d].account-id: %w", poolIndex, accountIndex, err)
				}
				if err := validateOpaquePoolID(account.EntitlementID); err != nil {
					return fmt.Errorf("account-pools[%d].accounts[%d].entitlement-id: %w", poolIndex, accountIndex, err)
				}
			}
			for _, atom := range []struct {
				kind string
				id   string
			}{
				{kind: "account", id: account.AccountID},
				{kind: "entitlement", id: account.EntitlementID},
			} {
				key := account.Provider + "\x00" + atom.kind + "\x00" + atom.id
				if previousPool, exists := accountAtoms[key]; exists && previousPool != poolIndex {
					return fmt.Errorf("account-pools[%d] %s %q overlaps pool %d", poolIndex, atom.kind, atom.id, previousPool)
				}
				accountAtoms[key] = poolIndex
			}
		}
	}
	return nil
}

func normalizePoolUUID(value string) (string, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func validateOpaquePoolID(value string) error {
	if value == "" {
		return fmt.Errorf("must be nonempty")
	}
	if len([]byte(value)) > 256 {
		return fmt.Errorf("must be at most 256 bytes")
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("must not have whitespace at either edge")
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return fmt.Errorf("must not contain control characters")
		}
	}
	return nil
}

// validatePoolLiveRelay enforces the mandatory relay for human live pools.
func validatePoolLiveRelay(cfg *Config) error {
	if cfg == nil || cfg.AccountPools == nil {
		return nil
	}
	for _, pool := range *cfg.AccountPools {
		if pool.Class == PoolClassHuman && !cfg.Codex.LiveMediaRelay.Enabled {
			return fmt.Errorf("human account-pools require codex.live-media-relay.enabled: true")
		}
	}
	return nil
}
