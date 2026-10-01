package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"testing"
)

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
