package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"testing"
)

func TestR3ServiceFrozenPolicyRevalidatesUnsafeModes(t *testing.T) {
	for _, mode := range []string{"ws-auth", "plugins", "Home"} {
		t.Run(mode, func(t *testing.T) {
			key := t.Name()
			old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []config.APIKeyPolicy{r3ServicePolicy(key)}}, WebsocketAuth: true}
			s := &Service{cfg: old}
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
			if s.commitConfigUpdate(next).cfg != nil {
				t.Fatal("unsafe effective service config accepted")
			}
			if len(s.cfg.APIKeyPolicies) != 1 || !s.cfg.WebsocketAuth || s.cfg.Home.Enabled || s.cfg.Plugins.Enabled {
				t.Fatal("unsafe effective service config published")
			}
		})
	}
}
