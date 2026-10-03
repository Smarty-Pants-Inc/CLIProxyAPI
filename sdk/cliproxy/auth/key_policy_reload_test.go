package auth

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	log "github.com/sirupsen/logrus"
)

func TestR3KeyPolicyReloadKeepsExistingState(t *testing.T) {
	for _, path := range []string{"SetConfig", "SetConfigSnapshot", "ApplyConfig"} {
		for _, change := range []string{"added", "removed", "changed"} {
			t.Run(path+"/"+change, func(t *testing.T) {
				key := t.Name()
				old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}}, WebsocketAuth: true}
				if change != "added" {
					old.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: keyDigest(key), AllowedAuths: []string{"A"}, DailyRequestCap: policyInt(10)}}
				}
				m := NewManager(nil, nil, nil)
				m.SetConfig(old)
				next := old.CloneForRuntime()
				next.Debug = true
				switch change {
				case "added":
					next.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: keyDigest(key), AllowedAuths: []string{"B"}}}
				case "removed":
					next.APIKeyPolicies = nil
				case "changed":
					next.APIKeyPolicies[0].AllowedAuths = []string{"B"}
					next.APIKeyPolicies[0].DailyRequestCap = policyInt(0)
				}
				var warnings bytes.Buffer
				previous := log.StandardLogger().Out
				log.SetOutput(&warnings)
				defer log.SetOutput(previous)
				for range 2 {
					switch path {
					case "SetConfig":
						m.SetConfig(next)
					case "SetConfigSnapshot":
						m.SetConfigSnapshot(next)
					case "ApplyConfig":
						if !m.ApplyConfigWithCooldownStateStore(context.Background(), next, nil) {
							t.Fatal("apply failed")
						}
					}
				}
				got := m.KeyPolicies(key)
				if !reflect.DeepEqual(got, old.APIKeyPolicies) {
					t.Fatalf("%s policy published before restart: got=%+v want=%+v", change, got, old.APIKeyPolicies)
				}
				cfg, _ := m.runtimeConfig.Load().(*config.Config)
				if !cfg.Debug {
					t.Fatal("unrelated reload setting lost")
				}
				warning := "client-key policy change for " + keyDigest(key) + " takes effect on restart"
				if strings.Count(warnings.String(), warning) != 1 || strings.Contains(warnings.String(), key) {
					t.Fatalf("unsafe/repeated warning: %q", warnings.String())
				}
				restarted := NewManager(nil, nil, nil)
				restarted.SetConfig(next)
				if !reflect.DeepEqual(restarted.KeyPolicies(key), next.APIKeyPolicies) {
					t.Fatal("restart did not adopt policy")
				}
			})
		}
	}
}

func TestR3KeyPolicyReloadNewKeyAndReaddedKey(t *testing.T) {
	key := t.Name() + "-old"
	newKey := t.Name() + "-new"
	m := NewManager(nil, nil, nil)
	m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}}, WebsocketAuth: true})
	next := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key, newKey}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: keyDigest(newKey), AllowedAuths: []string{"A"}}}}, WebsocketAuth: true}
	m.SetConfig(next)
	if got := m.KeyPolicies(newKey); len(got) != 1 || got[0].AllowedAuths[0] != "A" {
		t.Fatalf("new key policy not applied: %+v", got)
	}
	m.SetConfig(&config.Config{WebsocketAuth: true})
	next.APIKeyPolicies = append(next.APIKeyPolicies, config.APIKeyPolicy{KeySHA256: keyDigest(key)})
	m.SetConfig(next)
	if len(m.KeyPolicies(key)) != 0 {
		t.Fatal("removed/re-added old key treated as new")
	}
	if len(m.KeyPolicies(newKey)) != 1 {
		t.Fatal("removed/re-added new key lost its original policy")
	}
}
