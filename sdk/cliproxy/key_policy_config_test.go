package cliproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestKeyPolicySDKRejectsInvalidConfiguration(t *testing.T) {
	digest := sha256.Sum256([]byte("key"))
	valid := hex.EncodeToString(digest[:])
	for _, spelling := range []string{strings.ToUpper(valid), "malformed", strings.Repeat("0", 64), valid} {
		cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"key"}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: spelling}}}, WebsocketAuth: true}
		if spelling == valid {
			cfg.APIKeyPolicies = append(cfg.APIKeyPolicies, cfg.APIKeyPolicies[0])
		}
		if _, err := NewBuilder().WithConfig(cfg).WithConfigPath("unused.yaml").Build(); err == nil {
			t.Errorf("SDK accepted explicit invalid policy %q", spelling)
		}
		previous := &config.Config{}
		s := &Service{cfg: previous}
		if commit := s.commitConfigUpdate(cfg); commit.cfg != nil || s.cfg != previous {
			t.Errorf("reload published invalid policy %q", spelling)
		}
	}
}

func TestHomeDoesNotErasePoliciedClientIdentity(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"key"}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: "digest"}}}, WebsocketAuth: true}
	forceHomeRuntimeConfig(cfg)
	if len(cfg.APIKeys) != 1 || !cfg.WebsocketAuth {
		t.Fatal("Home erased policy authentication")
	}
	cfg.APIKeyPolicies = nil
	forceHomeRuntimeConfig(cfg)
	if len(cfg.APIKeys) != 0 || cfg.WebsocketAuth {
		t.Fatal("unpolicied Home changed")
	}
}
