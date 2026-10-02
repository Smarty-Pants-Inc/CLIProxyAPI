package api

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestR3ServerFrozenPolicyRevalidatesUnsafeModes(t *testing.T) {
	for _, mode := range []string{"ws-auth", "plugins", "Home"} {
		t.Run(mode, func(t *testing.T) {
			key := t.Name()
			old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []config.APIKeyPolicy{r3APIPolicy(key)}}, WebsocketAuth: true}
			s := newTestServerWithConfig(t, old)
			next := old.CloneForRuntime()
			next.APIKeyPolicies = nil
			switch mode {
			case "ws-auth":
				next.WebsocketAuth = false
			case "plugins":
				next.Plugins.Enabled = true
			case "Home":
				next.Home.Enabled = true
			}
			if s.UpdateClientsContext(context.Background(), next) {
				t.Fatal("unsafe effective server config accepted")
			}
			if len(s.cfg.APIKeyPolicies) != 1 || !s.wsAuthEnabled.Load() || s.cfg.Home.Enabled || s.cfg.Plugins.Enabled {
				t.Fatal("unsafe effective server config published")
			}
		})
	}
}
