package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigDirectYAMLDecodePreservesNonSDKAndRuntimeStateInPoolMode(t *testing.T) {
	capZero := int64(0)
	key := "pool-client"
	history := map[string]APIKeyPolicyReloadState{
		APIKeyDigest(key): {Warned: true},
	}
	cfg := Config{
		SDKConfig: SDKConfig{
			PolicyReloadState: history,
		},
		Home:          HomeConfig{Host: "runtime-home"},
		Pprof:         PprofConfig{Addr: "initial-pprof"},
		RequestRetry:  7,
		LoggingToFile: true,
	}
	raw := "host: pooled-host\nport: 9999\nws-auth: true\napi-keys: [pool-client]\naccount-pools:\n  - id: pool\n    org: org\n    class: agent\n    max-in-flight: 0\n    accounts: []\napi-key-policies:\n  - key-sha256: " + APIKeyDigest(key) + "\n    pool: pool\n"

	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("direct pooled Config decode failed: %v", err)
	}
	if cfg.Host != "pooled-host" || cfg.Port != 9999 {
		t.Fatalf("server fields were not decoded: host=%q port=%d", cfg.Host, cfg.Port)
	}
	if cfg.AccountPools == nil || len(*cfg.AccountPools) != 1 || (*cfg.AccountPools)[0].MaxInFlight == nil || *(*cfg.AccountPools)[0].MaxInFlight != capZero {
		t.Fatalf("pool fields were not decoded: %+v", cfg.AccountPools)
	}
	if cfg.Home.Host != "runtime-home" || cfg.Pprof.Addr != "initial-pprof" || cfg.RequestRetry != 7 || !cfg.LoggingToFile {
		t.Fatalf("defaults/runtime-only state was lost: home=%+v pprof=%+v retry=%d logging=%t", cfg.Home, cfg.Pprof, cfg.RequestRetry, cfg.LoggingToFile)
	}
	if _, ok := cfg.PolicyReloadState[APIKeyDigest(key)]; !ok {
		t.Fatal("runtime policy history was lost")
	}
}

func TestConfigDirectYAMLDecodePreservesNonSDKAndRuntimeStateInLegacyMode(t *testing.T) {
	key := "legacy-client"
	cfg := Config{
		SDKConfig: SDKConfig{
			PolicyReloadState: map[string]APIKeyPolicyReloadState{APIKeyDigest(key): {Warned: true}},
		},
		Home:          HomeConfig{Host: "runtime-home"},
		Pprof:         PprofConfig{Addr: "initial-pprof"},
		RequestRetry:  8,
		LoggingToFile: true,
	}

	if err := yaml.Unmarshal([]byte("host: legacy-host\nws-auth: true\n"), &cfg); err != nil {
		t.Fatalf("direct legacy Config decode failed: %v", err)
	}
	if cfg.AccountPools != nil {
		t.Fatalf("legacy decode enabled account pools: %+v", cfg.AccountPools)
	}
	if cfg.Host != "legacy-host" || cfg.Home.Host != "runtime-home" || cfg.Pprof.Addr != "initial-pprof" || cfg.RequestRetry != 8 || !cfg.LoggingToFile {
		t.Fatalf("legacy server/default/runtime state changed: host=%q home=%+v pprof=%+v retry=%d logging=%t", cfg.Host, cfg.Home, cfg.Pprof, cfg.RequestRetry, cfg.LoggingToFile)
	}
	if _, ok := cfg.PolicyReloadState[APIKeyDigest(key)]; !ok {
		t.Fatal("legacy runtime policy history was lost")
	}
}
