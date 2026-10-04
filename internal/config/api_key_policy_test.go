package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPIKeyPolicyConfig(t *testing.T) {
	hash := sha256.Sum256([]byte("key"))
	digest := hex.EncodeToString(hash[:])
	if (&Config{Home: HomeConfig{Enabled: true}, SDKConfig: SDKConfig{APIKeyPolicies: []APIKeyPolicy{{KeySHA256: digest}}}}).ValidateAPIKeyPolicies() == nil {
		t.Fatal("runtime Home policy accepted")
	}
	for _, tc := range []struct {
		name, body string
		bad        bool
	}{
		{"explicit deny", "ws-auth: true\napi-key-policies:\n- key-sha256: " + digest + "\n  allowed-auths: []\n  allowed-models: []\n  daily-token-cap: 0\n", false},
		{"escaped key", "\"api-key-polici\\u0065s\": [{key-sha256: bad}]", true},
		{"trailing document", "{}\n---\napi-key-policies: []", true},
		{"unconfigured key", "api-key-policies: [{key-sha256: " + strings.Repeat("a", 64) + "}]", true},
		{"negative", "api-key-policies: [{key-sha256: " + digest + ", daily-token-cap: -1}]", true},
		{"plugins", "plugins: {enabled: true}\napi-key-policies: [{key-sha256: " + digest + "}]", true},
		{"ws bypass", "ws-auth: false\napi-key-policies: [{key-sha256: " + digest + "}]", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte("api-keys: [key]\n" + tc.body))
			if (err != nil) != tc.bad {
				t.Fatalf("parse=%v", err)
			}
			if tc.bad {
				return
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("api-keys: [key]\n"+tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := saveConfigFixture(path, cfg); err != nil {
				t.Fatal(err)
			}
			cfg, err = LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			p := cfg.APIKeyPolicies[0]
			if p.AllowedModels == nil || len(*p.AllowedModels) != 0 || p.DailyTokenCap == nil || *p.DailyTokenCap != 0 {
				t.Fatal("explicit deny lost")
			}
		})
	}
}
