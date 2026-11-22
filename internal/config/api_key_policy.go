package config

import (
	"bytes"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// APIKeyPolicy uses exact, case-sensitive runtime auth IDs and client model names.
// Nil models/caps mean unlimited; empty models/auths and zero caps deny.
type APIKeyPolicy struct {
	KeySHA256       string    `yaml:"key-sha256" json:"key-sha256"`
	Pool            string    `yaml:"pool,omitempty" json:"pool,omitempty"`
	AllowedAuths    []string  `yaml:"allowed-auths" json:"allowed-auths"`
	AllowedModels   *[]string `yaml:"allowed-models,omitempty" json:"allowed-models,omitempty"`
	DailyTokenCap   *int64    `yaml:"daily-token-cap,omitempty" json:"daily-token-cap,omitempty"`
	DailyRequestCap *int64    `yaml:"daily-request-cap,omitempty" json:"daily-request-cap,omitempty"`
}

// MarshalYAML keeps pooled policies valid on round-trip: nil allowed-auths is
// omitted, while an explicit empty slice remains representable for legacy mode.
func (policy APIKeyPolicy) MarshalYAML() (any, error) {
	type plain APIKeyPolicy
	var node yaml.Node
	if err := node.Encode(plain(policy)); err != nil {
		return nil, err
	}
	if policy.Pool != "" && policy.AllowedAuths == nil {
		removeMapKey(&node, "allowed-auths")
	}
	return &node, nil
}

func (cfg *Config) ValidateAPIKeyPolicies() error {
	if cfg == nil {
		return nil
	}
	if cfg.AccountPools != nil {
		if cfg.Home.Enabled || cfg.Plugins.Enabled {
			return fmt.Errorf("account-pools are unavailable with Home or plugins")
		}
		if !cfg.WebsocketAuth {
			return fmt.Errorf("account-pools requires ws-auth: true")
		}
	} else if len(cfg.APIKeyPolicies) != 0 {
		if cfg.Home.Enabled || cfg.Plugins.Enabled {
			return fmt.Errorf("api-key-policies is unavailable with Home or plugins")
		}
		if !cfg.WebsocketAuth {
			return fmt.Errorf("api-key-policies requires ws-auth: true")
		}
	}
	if err := validateAccountPoolConfiguration(cfg.AccountPools, cfg.APIKeys, cfg.APIKeyPolicies); err != nil {
		return err
	}
	return validatePoolLiveRelay(cfg)
}

// Reused from #28: parsed document validation must not depend on raw key spelling.
func validateSingleConfigDocument(data []byte) error {
	d := yaml.NewDecoder(bytes.NewReader(data))
	var n yaml.Node
	if err := d.Decode(&n); err != nil {
		return err
	}
	if err := d.Decode(&n); err != io.EOF {
		return fmt.Errorf("config must contain one YAML document")
	}
	return nil
}
