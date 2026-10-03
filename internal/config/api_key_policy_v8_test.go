package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAPIKeyPolicyV8MigrationPreservesExplicitDeny(t *testing.T) {
	digest := APIKeyDigest("policy-v8-client")
	policy := fmt.Sprintf("- key-sha256: %s\n  allowed-auths: []\n  allowed-models: []\n  daily-token-cap: 0\n  daily-request-cap: 0\n", digest)
	legacy := "api-keys: [policy-v8-client]\nws-auth: true\napi-key-policies:\n" + policy
	v8 := "config-version: 8\naccess:\n  api-keys: [policy-v8-client]\n  api-key-policies:\n" + "  " + strings.ReplaceAll(strings.TrimSuffix(policy, "\n"), "\n", "\n  ") + "\n"
	for name, body := range map[string]string{"legacy": legacy, "v8": v8} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.APIKeyPolicies) != 1 || cfg.APIKeyPolicies[0].AllowedModels == nil || len(*cfg.APIKeyPolicies[0].AllowedModels) != 0 || cfg.APIKeyPolicies[0].DailyTokenCap == nil || *cfg.APIKeyPolicies[0].DailyTokenCap != 0 || cfg.APIKeyPolicies[0].DailyRequestCap == nil || *cfg.APIKeyPolicies[0].DailyRequestCap != 0 {
				t.Fatal("explicit deny policy missing on initial parse")
			}
			original := cfg.APIKeyPolicies
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err = os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			for save := 0; save < 2; save++ {
				if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
					t.Fatal(err)
				}
				data, errRead := os.ReadFile(path)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if err = ValidateV8Config(data); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), "  api-key-policies:") {
					t.Fatalf("policy was not migrated under access: %s", data)
				}
				cfg, err = LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(cfg.APIKeyPolicies, original) {
					t.Fatalf("v8 migration changed policy: got %+v want %+v", cfg.APIKeyPolicies, original)
				}
			}
		})
	}
}

func TestAPIKeyPolicyV8RejectsUnsafeConfiguration(t *testing.T) {
	base := "config-version: 8\naccess:\n  api-keys: [policy-v8-client]\n  api-key-policies:\n    - key-sha256: " + APIKeyDigest("policy-v8-client") + "\n"
	for name, extra := range map[string]string{
		"websocket bypass": "oauth:\n  providers:\n    aistudio:\n      ws-auth: false\n",
		"plugins":          "plugins:\n  enabled: true\n",
		"negative cap":     "      daily-token-cap: -1\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfigBytes([]byte(base + extra)); err == nil {
				t.Fatal("unsafe v8 policy configuration accepted")
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(base+extra), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatal("unsafe v8 policy file accepted")
			}
		})
	}
}
