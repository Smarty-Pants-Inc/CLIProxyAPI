package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

// Adding a standalone SDK decoder must not make yaml.v3 drop the embedded SDK
// fields from full Config snapshots or the comment-preserving save encoder.
func TestConfigYAMLMarshalPreservesEmbeddedSDKFields(t *testing.T) {
	zero := int64(0)
	models := []string{}
	key := "marshal-client"
	for _, pooled := range []bool{false, true} {
		cfg := Config{
			SDKConfig: SDKConfig{
				APIKeys: []string{key},
				APIKeyPolicies: []APIKeyPolicy{{
					KeySHA256: APIKeyDigest(key), AllowedAuths: []string{},
					AllowedModels: &models, DailyTokenCap: &zero,
				}},
			},
			Host: "marshal-host", Port: 9999, WebsocketAuth: true,
		}
		if pooled {
			cfg.AccountPools = &[]AccountPool{{ID: "pool", Org: "org", Class: PoolClassAgent, MaxInFlight: &zero, Accounts: []PoolAccount{}}}
			cfg.APIKeyPolicies[0].Pool = "pool"
			cfg.APIKeyPolicies[0].AllowedAuths = nil
			cfg.APIKeyPolicies[0].DailyTokenCap = nil
		}
		for name, snapshot := range map[string]any{
			"Config value": cfg, "Config pointer": &cfg,
			"legacy value": legacyConfig(cfg), "legacy pointer": (*legacyConfig)(&cfg),
		} {
			t.Run(name+map[bool]string{false: "/legacy", true: "/pooled"}[pooled], func(t *testing.T) {
				raw, err := yaml.Marshal(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				var decoded Config
				if err := yaml.Unmarshal(raw, &decoded); err != nil {
					t.Fatalf("full snapshot did not decode: %v\n%s", err, raw)
				}
				if decoded.Host != cfg.Host || decoded.Port != cfg.Port || !decoded.WebsocketAuth {
					t.Fatalf("full snapshot lost non-SDK fields: %s", raw)
				}
				if !reflect.DeepEqual(decoded.APIKeys, cfg.APIKeys) || !reflect.DeepEqual(decoded.APIKeyPolicies, cfg.APIKeyPolicies) || !reflect.DeepEqual(decoded.AccountPools, cfg.AccountPools) {
					t.Fatalf("full snapshot lost embedded SDK policy fields: %s", raw)
				}
			})
		}
	}
}
