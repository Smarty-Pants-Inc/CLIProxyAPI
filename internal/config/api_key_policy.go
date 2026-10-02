package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// APIKeyPolicy uses exact, case-sensitive runtime auth IDs and client model names.
// Nil models/caps mean unlimited; empty models/auths and zero caps deny.
type APIKeyPolicy struct {
	KeySHA256       string    `yaml:"key-sha256" json:"key-sha256"`
	AllowedAuths    []string  `yaml:"allowed-auths" json:"allowed-auths"`
	AllowedModels   *[]string `yaml:"allowed-models,omitempty" json:"allowed-models,omitempty"`
	DailyTokenCap   *int64    `yaml:"daily-token-cap,omitempty" json:"daily-token-cap,omitempty"`
	DailyRequestCap *int64    `yaml:"daily-request-cap,omitempty" json:"daily-request-cap,omitempty"`
}

func (cfg *Config) ValidateAPIKeyPolicies() error {
	if len(cfg.APIKeyPolicies) != 0 && (cfg.Home.Enabled || cfg.Plugins.Enabled) {
		return fmt.Errorf("api-key-policies is unavailable with Home or plugins")
	}
	if len(cfg.APIKeyPolicies) != 0 && !cfg.WebsocketAuth {
		return fmt.Errorf("api-key-policies requires ws-auth: true")
	}
	keys := map[string]bool{}
	for _, key := range cfg.APIKeys {
		b := sha256.Sum256([]byte(strings.TrimSpace(key)))
		keys[hex.EncodeToString(b[:])] = true
	}
	seen := map[string]bool{}
	for _, p := range cfg.APIKeyPolicies {
		b, err := hex.DecodeString(p.KeySHA256)
		if err != nil || len(b) != 32 || strings.ToLower(p.KeySHA256) != p.KeySHA256 || seen[p.KeySHA256] || !keys[p.KeySHA256] {
			return fmt.Errorf("invalid, unconfigured or duplicate api-key-policy key-sha256")
		}
		seen[p.KeySHA256] = true
		for _, cap := range []*int64{p.DailyTokenCap, p.DailyRequestCap} {
			if cap != nil && *cap < 0 {
				return fmt.Errorf("api-key-policy caps must be nonnegative")
			}
		}
	}
	return nil
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
