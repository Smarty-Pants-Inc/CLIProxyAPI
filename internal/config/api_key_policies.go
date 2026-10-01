package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// A second YAML document must not silently hide or remove a security policy.
func validateSingleConfigDocument(data []byte) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return err
	}
	if err := decoder.Decode(&node); !errors.Is(err, io.EOF) {
		return fmt.Errorf("config must contain exactly one YAML document")
	}
	return nil
}

// APIKeyPolicy restricts a client key to named upstream credentials. The key itself
// remains in api-keys; this block contains only its SHA-256 digest.
type APIKeyPolicy struct {
	KeySHA256        string   `yaml:"key-sha256" json:"key-sha256"`
	AllowedAuths     []string `yaml:"allowed-auths" json:"allowed-auths"`
	AllowedProviders []string `yaml:"allowed-providers,omitempty" json:"allowed-providers,omitempty"`
	// Nil means unrestricted; an explicit empty list denies every model.
	AllowedModels *[]string `yaml:"allowed-models,omitempty" json:"allowed-models,omitempty"`
	// Nil means no cap; zero denies generation immediately.
	DailyTokenCap *int64 `yaml:"daily-token-cap,omitempty" json:"daily-token-cap,omitempty"`
	// Nil means no request cap; zero denies request admission immediately.
	DailyRequestCap *int64 `yaml:"daily-request-cap,omitempty" json:"daily-request-cap,omitempty"`
	// SingleAttempt disables retries, credential rotation and cooldown waits.
	SingleAttempt bool `yaml:"single-attempt,omitempty" json:"single-attempt,omitempty"`
}

// ValidateAPIKeyPolicies rejects ambiguous or malformed policies instead of dropping
// them, which would silently turn a restricted client into an unrestricted one.
func (cfg *Config) ValidateAPIKeyPolicies() error {
	if len(cfg.APIKeyPolicies) > 0 && !cfg.WebsocketAuth {
		return fmt.Errorf("api-key-policies requires ws-auth: true")
	}
	seen := make(map[string]bool, len(cfg.APIKeyPolicies))
	for i := range cfg.APIKeyPolicies {
		policy := &cfg.APIKeyPolicies[i]
		policy.KeySHA256 = strings.ToLower(strings.TrimSpace(policy.KeySHA256))
		digest, err := hex.DecodeString(policy.KeySHA256)
		if err != nil || len(digest) != 32 {
			return fmt.Errorf("api-key-policies[%d]: key-sha256 must be a 64-character SHA-256 hex digest", i)
		}
		if seen[policy.KeySHA256] {
			return fmt.Errorf("api-key-policies[%d]: duplicate key-sha256", i)
		}
		seen[policy.KeySHA256] = true
		for j, pattern := range policy.AllowedAuths {
			if strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("api-key-policies[%d]: allowed-auths[%d] is empty", i, j)
			}
			if _, errMatch := path.Match(pattern, ""); errMatch != nil {
				return fmt.Errorf("api-key-policies[%d]: allowed-auths[%d] has invalid glob syntax", i, j)
			}
		}
		var models []string
		if policy.AllowedModels != nil {
			models = *policy.AllowedModels
		}
		for j, pattern := range models {
			if strings.TrimSpace(pattern) == "" {
				return fmt.Errorf("api-key-policies[%d]: allowed-models[%d] is empty", i, j)
			}
			if _, errMatch := path.Match(pattern, ""); errMatch != nil {
				return fmt.Errorf("api-key-policies[%d]: allowed-models[%d] has invalid glob syntax", i, j)
			}
		}
		if policy.DailyTokenCap != nil && *policy.DailyTokenCap < 0 {
			return fmt.Errorf("api-key-policies[%d]: daily-token-cap must be nonnegative", i)
		}
		if policy.DailyRequestCap != nil && *policy.DailyRequestCap < 0 {
			return fmt.Errorf("api-key-policies[%d]: daily-request-cap must be nonnegative", i)
		}
		for j, provider := range policy.AllowedProviders {
			provider = strings.ToLower(strings.TrimSpace(provider))
			if provider == "" || strings.ContainsAny(provider, "*?[]\\/") {
				return fmt.Errorf("api-key-policies[%d]: allowed-providers[%d] must be an exact provider name", i, j)
			}
			policy.AllowedProviders[j] = provider
		}
	}
	return nil
}
