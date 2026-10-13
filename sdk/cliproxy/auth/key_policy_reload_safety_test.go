package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestR3ManagerFrozenPolicyRevalidatesUnsafeModes(t *testing.T) {
	for _, path := range []string{"SetConfig", "SetConfigSnapshot", "ApplyConfig"} {
		for _, mode := range []string{"ws-auth", "plugins", "Home"} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				key := t.Name()
				old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: keyDigest(key)}}}, WebsocketAuth: true}
				m := NewManager(nil, nil, nil)
				m.SetConfig(old)
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
				switch path {
				case "SetConfig":
					m.SetConfig(next)
				case "SetConfigSnapshot":
					m.SetConfigSnapshot(next)
				case "ApplyConfig":
					if m.ApplyConfigWithCooldownStateStore(context.Background(), next, nil) {
						t.Error("unsafe reload reported accepted")
					}
				}
				current, _ := m.runtimeConfig.Load().(*config.Config)
				if len(m.KeyPolicies(key)) != 1 || !current.WebsocketAuth || current.Plugins.Enabled || current.Home.Enabled {
					t.Fatal("frozen policy allowed unsafe effective config")
				}
			})
		}
	}
}
