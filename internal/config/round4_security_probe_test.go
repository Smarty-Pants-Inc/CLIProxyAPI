package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRound4InjectedPlatformProtectionRefuses(t *testing.T) {
	for _, platform := range []string{"Darwin deny ACL", "Windows service-reader DACL", "Windows security attributes"} {
		t.Run(platform, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			original := []byte("api-keys: [fixture-original]\n")
			if err := os.WriteFile(path, original, 0640); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Stat(path)
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			seen := false
			err = verifyOriginalConfigSecurity(source, before, platform, func(file *os.File) error {
				seen = true
				info, _ := file.Stat()
				if !os.SameFile(before, info) {
					t.Fatal("probe not given stable original")
				}
				return errors.New("cannot reproduce original policy")
			})
			if !seen || err == nil || !strings.Contains(err.Error(), "publication refused") {
				t.Fatalf("unsupported protection accepted: %v", err)
			}
			after, _ := os.Stat(path)
			raw, _ := os.ReadFile(path)
			if !os.SameFile(before, after) || string(raw) != string(original) {
				t.Fatal("refusal changed original inode or bytes")
			}
		})
	}
}

func TestRound4UnsupportedMACDecision(t *testing.T) {
	for _, name := range []string{"security.SMACK64", "security.SMACK64EXEC", "security.apparmor", "security.future_policy"} {
		if err := refuseUnsupportedConfigAttributes([]string{"user.note", name}, "security.selinux"); err == nil {
			t.Fatalf("unsupported mandatory attribute %s accepted", name)
		}
	}
	if err := refuseUnsupportedConfigAttributes([]string{"user.note", "security.selinux"}, "security.selinux"); err != nil {
		t.Fatal(err)
	}
}

func TestRound4OriginalProbeFailureAndIdentityChangeRefuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	before, _ := source.Stat()
	if err := verifyOriginalConfigSecurity(source, before, "probe", func(*os.File) error { return os.ErrPermission }); err == nil {
		t.Fatal("probe failure accepted")
	}
	other := filepath.Join(t.TempDir(), "other")
	if err := os.WriteFile(other, nil, 0600); err != nil {
		t.Fatal(err)
	}
	otherInfo, _ := os.Stat(other)
	if err := verifyOriginalConfigSecurity(source, otherInfo, "probe", func(*os.File) error { t.Fatal("probe ran against wrong inode"); return nil }); err == nil {
		t.Fatal("identity mismatch accepted")
	}
}
