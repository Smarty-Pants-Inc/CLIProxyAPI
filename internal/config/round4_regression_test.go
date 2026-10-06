package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound4FailedPublicationCleansCandidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("api-keys: [fixture-original]\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	for i := 0; i < 12; i++ {
		err := atomicWriteConfigWithRename(path, []byte("api-keys: [fixture-candidate]\n"), func(string, string) error { return errors.New("injected rename refusal") })
		if err == nil {
			t.Fatal("rename refusal accepted")
		}
	}
	after, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || string(raw) != string(original) {
		t.Fatal("original changed")
	}
	candidates, err := filepath.Glob(filepath.Join(dir, ".config-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("failed publication retained %d credential-bearing candidates", len(candidates))
	}
}

// These source-contract checks run on the exact Linux baseline, where foreign
// platform implementations cannot be executed. Behavioral injected-probe tests
// accompany them; neither is claimed as native ACL/DACL execution evidence.
func TestRound4PlatformProtectionWiring(t *testing.T) {
	for _, tc := range []struct{ name, file, required string }{
		{"Darwin original deny ACL", "config_security_label_darwin.go", "probeDarwinConfigProtection"},
		{"Linux unsupported MAC", "config_security_label_linux.go", "refuseUnsupportedConfigAttributes"},
		{"Windows service reader", "config_security_label_windows.go", "verifyOriginalConfigSecurity"},
		{"Darwin same-inode lock", "config_lock_identity_unix.go", "//go:build linux || darwin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(tc.file)
			if err != nil || !strings.Contains(string(raw), tc.required) {
				t.Fatalf("required original-boundary guard missing: %s: %v", tc.file, err)
			}
		})
	}
}

func TestRound4FingerprintErrorIsBounded(t *testing.T) {
	err := ValidateClaudeFingerprintProfile(strings.Repeat("x", 6<<20))
	if err == nil || len(err.Error()) > 256 {
		t.Fatalf("unbounded invalid-profile error: bytes=%d", len(err.Error()))
	}
}
