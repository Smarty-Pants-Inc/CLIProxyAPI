package cliproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func r3ServicePolicy(key string) config.APIKeyPolicy {
	b := sha256.Sum256([]byte(key))
	return config.APIKeyPolicy{KeySHA256: hex.EncodeToString(b[:]), AllowedAuths: []string{"A"}}
}

func TestR3ServiceReloadFreezesExistingPolicies(t *testing.T) {
	for _, change := range []string{"added", "removed", "changed"} {
		t.Run(change, func(t *testing.T) {
			key := t.Name()
			old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}}, WebsocketAuth: true}
			if change != "added" {
				old.APIKeyPolicies = []config.APIKeyPolicy{r3ServicePolicy(key)}
			}
			next := old.CloneForRuntime()
			next.Debug = true
			switch change {
			case "added":
				next.APIKeyPolicies = []config.APIKeyPolicy{r3ServicePolicy(key)}
			case "removed":
				next.APIKeyPolicies = nil
			case "changed":
				next.APIKeyPolicies[0].AllowedAuths = []string{"B"}
			}
			m := coreauth.NewManager(nil, nil, nil)
			m.SetConfig(old)
			s := &Service{cfg: old, coreManager: m}
			serverReached := false
			s.updateServerClientsContextFn = func(_ context.Context, cfg *config.Config) bool {
				serverReached = true
				if !reflect.DeepEqual(cfg.APIKeyPolicies, old.APIKeyPolicies) {
					t.Error("server received hot policy mutation")
				}
				return false // Concrete partial-update exit after manager publication.
			}
			if s.applyConfigUpdateWithAuthSynthesis(context.Background(), next, false) {
				t.Fatal("failing runtime step succeeded")
			}
			if !serverReached {
				t.Fatal("runtime update did not reach failure probe")
			}
			if !reflect.DeepEqual(s.cfg.APIKeyPolicies, old.APIKeyPolicies) || !reflect.DeepEqual(m.KeyPolicies(key), old.APIKeyPolicies) {
				t.Fatal("failed partial reload published policy change")
			}
			if !s.cfg.Debug {
				t.Fatal("unrelated setting lost")
			}
			newKey := key + "-new"
			next.APIKeys = append(next.APIKeys, newKey)
			next.APIKeyPolicies = append(next.APIKeyPolicies, r3ServicePolicy(newKey))
			commit := s.commitConfigUpdate(next)
			if commit.cfg == nil || !s.applyManagerConfig(context.Background(), commit) || len(m.KeyPolicies(newKey)) != 1 {
				t.Fatal("new policied key not admitted on reload")
			}
		})
	}
}
