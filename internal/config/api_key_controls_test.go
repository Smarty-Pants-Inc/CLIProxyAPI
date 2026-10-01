package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAPIKeyPolicyModelAndCapOptionalRoundTrip(t *testing.T) {
	for _, initial := range []string{
		"api-key-policies: []\n",
		"host: localhost\n",
		"api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['*']}]\n",
		"api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['*'], allowed-models: null, daily-token-cap: null, daily-request-cap: null}]\n",
	} {
		for _, fields := range []string{"", ", allowed-models: [], daily-token-cap: 0, daily-request-cap: 0", ", allowed-models: [], daily-token-cap: 0, daily-request-cap: 100"} {
			cfg, err := ParseConfigBytes([]byte("api-key-policies: [{key-sha256: " + policyTestHash + ", allowed-auths: ['*']" + fields + "}]"))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "synthetic.yaml")
			if err := os.WriteFile(file, []byte(initial), 0600); err != nil {
				t.Fatal(err)
			}
			if err := SaveConfigPreserveComments(file, cfg); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(file)
			if err != nil {
				t.Fatal(err)
			}
			policy := loaded.APIKeyPolicies[0]
			if fields == "" {
				if policy.AllowedModels != nil || policy.DailyTokenCap != nil || policy.DailyRequestCap != nil {
					t.Fatal("absent optional controls gained restrictions")
				}
			} else {
				if policy.AllowedModels == nil || len(*policy.AllowedModels) != 0 || policy.DailyTokenCap == nil || *policy.DailyTokenCap != 0 || policy.DailyRequestCap == nil {
					t.Fatalf("explicit deny-all controls lost on save/load: initial=%q models=%v cap=%v", initial, policy.AllowedModels, policy.DailyTokenCap)
				}
				want := int64(0)
				if fields == ", allowed-models: [], daily-token-cap: 0, daily-request-cap: 100" {
					want = 100
				}
				if *policy.DailyRequestCap != want {
					t.Fatal("request cap changed on save/load")
				}
			}
		}
	}
}
