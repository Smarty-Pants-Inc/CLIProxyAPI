package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSecurity70V8KeyPolicies(t *testing.T) {
	key := "security70-client"
	policy := fmt.Sprintf("- key-sha256: %s\n  allowed-auths: [credential-A]\n  allowed-models: []\n  daily-request-cap: 0\n", APIKeyDigest(key))
	legacy := "api-keys: [" + key + "]\nws-auth: true\napi-key-policies:\n" + policy
	nested := "config-version: 8\naccess:\n  api-keys: [" + key + "]\n  api-key-policies:\n    - key-sha256: " + APIKeyDigest(key) + "\n      allowed-auths: [credential-A]\n      allowed-models: []\n      daily-request-cap: 0\noauth:\n  providers:\n    aistudio: {ws-auth: true}\n"
	for _, tc := range []struct{ name, text string }{{"legacy", legacy}, {"nested", nested}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.APIKeyPolicies) != 1 {
				t.Fatalf("policy silently ignored: %+v", cfg.APIKeyPolicies)
			}
			want := cfg.CloneForRuntime().APIKeyPolicies
			migrated, _, err := NormalizeConfigLayout([]byte(tc.text), true)
			if err != nil {
				t.Fatal(err)
			}
			var doc yaml.Node
			if err = yaml.Unmarshal(migrated, &doc); err != nil {
				t.Fatal(err)
			}
			if yamlPath(doc.Content[0], "access.api-key-policies") == nil || yamlPath(doc.Content[0], "api-key-policies") != nil {
				t.Fatalf("policy not migrated: %s", migrated)
			}
			if err = ValidateV8Config(migrated); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err = os.WriteFile(path, []byte(tc.text), 0600); err != nil {
				t.Fatal(err)
			}
			if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
				t.Fatal(err)
			}
			reloaded, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(want, reloaded.APIKeyPolicies) {
				t.Fatalf("policy changed on save/reload: %+v", reloaded.APIKeyPolicies)
			}
			saved, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = yaml.Unmarshal(saved, &doc); err != nil {
				t.Fatal(err)
			}
			if yamlPath(doc.Content[0], "access.api-key-policies") == nil || yamlPath(doc.Content[0], "api-key-policies") != nil {
				t.Fatalf("policy not persisted in v8: %s", saved)
			}
		})
	}
	t.Run("nested-presence-wins", func(t *testing.T) {
		cfg, err := ParseConfigBytes([]byte(legacy + "access: {api-key-policies: []}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.APIKeyPolicies) != 0 {
			t.Fatal("nested explicit empty did not override legacy")
		}
	})
}
