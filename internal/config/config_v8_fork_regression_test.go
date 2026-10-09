package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestForkV8MigrationPreservesAffinityQuotaAndHost(t *testing.T) {
	for _, age := range []int{0, 73} {
		t.Run(fmt.Sprint(age), func(t *testing.T) {
			dir := t.TempDir()
			authDir, stateDir := filepath.Join(dir, "auths"), filepath.Join(dir, "state")
			raw := []byte(fmt.Sprintf(`auth-dir: %q
routing:
  session-affinity: true
  session-affinity-state-dir: %q
  session-affinity-ttl: 6h
quota-exceeded:
  exhausted-reading-max-age-seconds: %d
codex-api-key:
  - api-key: synthetic-upstream
    base-url: https://endpoint.invalid
    headers:
      Host: authority.invalid
      X-Custom: retained
`, authDir, stateDir, age))
			migrated, _, err := NormalizeConfigLayout(raw, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = ValidateV8Config(migrated); err != nil {
				t.Fatal(err)
			}
			var doc yaml.Node
			if err = yaml.Unmarshal(migrated, &doc); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"routing.session-affinity-state-dir", "quota-exceeded.exhausted-reading-max-age-seconds"} {
				if yamlPath(doc.Content[0], path) == nil {
					t.Fatalf("v8 allowlist archived or dropped %s", path)
				}
			}
			path := filepath.Join(dir, "config.yaml")
			if err = WriteConfigAtomic(path, migrated); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			assertForkV8Values(t, cfg, stateDir, age)
			// Saving an unrelated setting must retain the fork's keys and Host
			// through both the runtime projection and canonical v8 tree.
			cfg.Debug = true
			if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
				t.Fatal(err)
			}
			cfg, err = LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			assertForkV8Values(t, cfg, stateDir, age)
			published, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = ValidateV8Config(published); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func assertForkV8Values(t *testing.T, cfg *Config, stateDir string, age int) {
	t.Helper()
	if !cfg.Routing.SessionAffinity || cfg.Routing.SessionAffinityStateDir != stateDir || cfg.Routing.SessionAffinityTTL != "6h" {
		t.Fatalf("affinity settings lost: %+v", cfg.Routing)
	}
	if cfg.QuotaExceeded.ExhaustedReadingMaxAgeSeconds == nil || *cfg.QuotaExceeded.ExhaustedReadingMaxAgeSeconds != age {
		t.Fatal("quota-reading expiry lost, including explicit zero")
	}
	if len(cfg.CodexKey) != 1 || cfg.CodexKey[0].Headers["Host"] != "authority.invalid" || cfg.CodexKey[0].Headers["X-Custom"] != "retained" {
		t.Fatal("configured Host authority or sibling header lost")
	}
	resolved, err := cfg.ResolveSessionAffinityStateDir()
	if err != nil || resolved != stateDir {
		t.Fatalf("state ownership directory changed: %q, %v", resolved, err)
	}
}

func TestForkV8RejectsAffinityStateInsideAuthDir(t *testing.T) {
	authDir := filepath.Join(t.TempDir(), "auths")
	raw := []byte(fmt.Sprintf("oauth: {auth-dir: %q}\nrouting: {session-affinity: false, session-affinity-state-dir: %q}\n", authDir, filepath.Join(authDir, "state")))
	migrated, _, err := NormalizeConfigLayout(raw, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseConfigBytes(migrated); !errors.Is(err, errAffinityStateInsideAuthDir) {
		t.Fatalf("v8 state path entered auth-dir: %v", err)
	}
}

func TestForkV8PreservesClientKeyPolicies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(fmt.Sprintf("api-keys: [synthetic-client]\nws-auth: true\napi-key-policies:\n  - key-sha256: %s\n    allowed-auths: []\n    allowed-models: []\n    daily-token-cap: 0\n    daily-request-cap: 0\n", APIKeyDigest("synthetic-client")))
	if err := WriteConfigAtomic(path, raw); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateV8Config(published); err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(published, &doc); err != nil {
		t.Fatal(err)
	}
	if yamlPath(doc.Content[0], "access.api-key-policies") == nil || yamlPath(doc.Content[0], "api-key-policies") != nil {
		t.Fatal("policy missing from canonical access section")
	}
	after, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.APIKeyPolicies) != 1 {
		t.Fatal("policy dropped by v8 migration")
	}
	p := after.APIKeyPolicies[0]
	if p.AllowedModels == nil || len(*p.AllowedModels) != 0 || len(p.AllowedAuths) != 0 || p.DailyTokenCap == nil || *p.DailyTokenCap != 0 || p.DailyRequestCap == nil || *p.DailyRequestCap != 0 {
		t.Fatalf("deny-by-empty/zero policy changed: %+v", p)
	}
}

func TestForkV8LoadCleanupUsesSnapshotRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	source := []byte("debug: true\nobservability: {logs: {debug: false}}\n")
	newer := []byte("observability: {logs: {debug: true}}\nserver: {port: 8999}\n")
	if err := WriteConfigAtomic(path, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigBytes(source, path, false); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("stale layout cleanup accepted newer file: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, newer) {
		t.Fatalf("cleanup replaced newer bytes: %v", err)
	}
	if err = WriteConfigAtomic(path, source); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Debug = true
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatalf("cleanup failed to advance the loaded source revision: %v", err)
	}
}

func TestForkV8HashUsesCanonicalPathAndRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	source := []byte("management: {secret-key: synthetic-old-secret}\n")
	newer := []byte("management: {secret-key: synthetic-new-secret}\n")
	if err := WriteConfigAtomic(path, newer); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigBytes(source, path, false); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("stale v8 hash overwrote a key rotation: %v", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, newer) {
		t.Fatalf("v8 key rotation overwritten: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeBcrypt(cfg.RemoteManagement.SecretKey) {
		t.Fatal("v8 management key was not hashed")
	}
	actual, err = os.ReadFile(path)
	if err != nil || bytes.Contains(actual, []byte("synthetic-new-secret")) || bytes.Contains(actual, []byte("remote-management:")) {
		t.Fatalf("hash published at wrong layout path: %v", err)
	}
	cfg.Debug = true
	if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
		t.Fatalf("hash did not advance the source revision: %v", err)
	}
}

func TestForkQuotaExpiryExplicitZeroSurvivesNewFieldSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteConfigAtomic(path, []byte("config-version: 8\n")); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	zero := 0
	cfg.QuotaExceeded.ExhaustedReadingMaxAgeSeconds = &zero
	if err = SaveConfigPreserveComments(path, cfg, true); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(path)
	if err != nil || cfg.QuotaExceeded.ExhaustedReadingMaxAgeSeconds == nil || *cfg.QuotaExceeded.ExhaustedReadingMaxAgeSeconds != 0 {
		t.Fatalf("explicit no-expiry setting pruned: %v", err)
	}
}

func TestForkV8TemplateAffinityTTL(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err = yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Content[0]
	if ttl := yamlPath(root, "routing.session-affinity-ttl"); ttl == nil || ttl.Value != "6h" {
		t.Fatal("template lost fork 6h affinity TTL")
	}
	if yamlPath(root, "routing.session-affinity-state-dir") == nil {
		t.Fatal("template lost separate state-directory key")
	}
	if !strings.Contains(string(data), "exhausted-reading-max-age-seconds") {
		t.Fatal("template lost quota expiry documentation")
	}
}
