package cliproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"reflect"
	"testing"

	internalaccess "github.com/router-for-me/CLIProxyAPI/v7/internal/access"
	configaccess "github.com/router-for-me/CLIProxyAPI/v7/internal/access/config_access"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func homeSecurityTestPolicy(key string, allowed ...string) config.APIKeyPolicy {
	digest := sha256.Sum256([]byte(key))
	return config.APIKeyPolicy{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: allowed}
}

func TestHomeOverlayRemoteKeyRemovalAndRotation(t *testing.T) {
	for _, replacement := range []string{"", "remote-rotated-K"} {
		t.Run(map[bool]string{true: "removal", false: "rotation"}[replacement == ""], func(t *testing.T) {
			local := &config.Config{SDKConfig: config.SDKConfig{
				APIKeys: []string{"local-L"}, APIKeyPolicies: []config.APIKeyPolicy{homeSecurityTestPolicy("local-L", "*.json")},
			}}
			local.Home.Enabled = true
			service := &Service{cfg: local, homeGeneration: 1}
			client, _ := newHomePluginTaskTestClient(t, nil, 0)
			ctx := context.Background()
			// A remote-added unpolicied key must be revoked for fresh requests,
			// not preserved as an unrestricted authentication bypass.
			first := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"remote-K"}}}
			work, errStage := service.stageHomeOverlayWithClient(ctx, first, client)
			if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
				t.Fatalf("first stage/commit: %v", errStage)
			}
			previous := service.cfg.CloneForRuntime()
			accessManager := sdkaccess.NewManager()
			t.Cleanup(func() { configaccess.Register(nil) })
			if _, err := internalaccess.ApplyAccessProviders(accessManager, nil, previous); err != nil {
				t.Fatal(err)
			}
			authenticate := func(key string) (*sdkaccess.Result, *sdkaccess.AuthError) {
				r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
				r.Header.Set("Authorization", "Bearer "+key)
				return accessManager.Authenticate(ctx, r)
			}
			if result, err := authenticate("remote-K"); result == nil || err != nil {
				t.Fatalf("first overlay did not admit remote key: result=%v err=%v", result, err)
			}
			second := &config.Config{}
			if replacement != "" {
				second.APIKeys = []string{replacement}
				second.APIKeyPolicies = []config.APIKeyPolicy{homeSecurityTestPolicy(replacement, "second.json")}
			}
			work, errStage = service.stageHomeOverlayWithClient(ctx, second, client)
			if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
				t.Fatalf("second stage/commit: %v", errStage)
			}
			wantKeys := []string{"local-L"}
			if replacement != "" {
				wantKeys = append(wantKeys, replacement)
			}
			if !reflect.DeepEqual(service.cfg.APIKeys, wantKeys) {
				t.Errorf("remote key revocation failed: keys = %v, want %v", service.cfg.APIKeys, wantKeys)
			}
			if _, err := internalaccess.ApplyAccessProviders(accessManager, previous, service.cfg); err != nil {
				t.Fatal(err)
			}
			if result, err := authenticate("remote-K"); result != nil || !sdkaccess.IsAuthErrorCode(err, sdkaccess.AuthErrorCodeInvalidCredential) {
				t.Errorf("fresh request still admitted revoked key: result=%v err=%v", result, err)
			}
			for _, key := range wantKeys {
				if result, err := authenticate(key); result == nil || err != nil {
					t.Errorf("current key %q not admitted: result=%v err=%v", key, result, err)
				}
			}
			wantPolicies := append([]config.APIKeyPolicy{local.APIKeyPolicies[0]}, second.APIKeyPolicies...)
			if !reflect.DeepEqual(service.cfg.APIKeyPolicies, wantPolicies) {
				t.Fatalf("stale remote policies retained: got %v, want %v", service.cfg.APIKeyPolicies, wantPolicies)
			}
			if !reflect.DeepEqual(previous.APIKeys, []string{"local-L", "remote-K"}) {
				t.Fatal("previous effective snapshot changed")
			}
		})
	}
}

func TestHomeOverlayAdmissionRestrictionsSurviveRelaxation(t *testing.T) {
	local := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"local-L"}, APIKeyPolicies: []config.APIKeyPolicy{homeSecurityTestPolicy("local-L", "*.json")},
	}}
	local.Home.Enabled = true
	service := &Service{cfg: local, homeGeneration: 1}
	client, _ := newHomePluginTaskTestClient(t, nil, 0)
	ctx := context.Background()
	remote := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"remote-K"}, APIKeyPolicies: []config.APIKeyPolicy{homeSecurityTestPolicy("local-L", "first.json")},
	}}
	work, errStage := service.stageHomeOverlayWithClient(ctx, remote, client)
	if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
		t.Fatalf("first stage/commit: %v", errStage)
	}
	admitted := coreauth.WithClientAPIKeyPolicies(ctx, "local-L", service.cfg.APIKeyPolicies)
	work, errStage = service.stageHomeOverlayWithClient(ctx, &config.Config{}, client)
	if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
		t.Fatalf("second stage/commit: %v", errStage)
	}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(service.cfg)
	auth := &coreauth.Auth{FileName: "second.json"}
	if errPolicy := manager.ValidateClientAuth(admitted, auth); errPolicy == nil {
		t.Fatal("prior admission restriction relaxed")
	}
	fresh := coreauth.WithClientAPIKeyPolicies(ctx, "local-L", service.cfg.APIKeyPolicies)
	if errPolicy := manager.ValidateClientAuth(fresh, auth); errPolicy != nil {
		t.Fatalf("fresh admission retained previous remote restriction: %v", errPolicy)
	}
	if !reflect.DeepEqual(service.cfg.APIKeys, []string{"local-L"}) {
		t.Fatalf("admission snapshots retained revoked remote key: %v", service.cfg.APIKeys)
	}
}

func TestHomeOverlayLocalBaselineIndependentAndReloadable(t *testing.T) {
	local := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"local-L"}, APIKeyPolicies: []config.APIKeyPolicy{homeSecurityTestPolicy("local-L", "local.json")},
	}}
	local.Home.Enabled = true
	service := &Service{cfg: local, homeGeneration: 1}
	client, _ := newHomePluginTaskTestClient(t, nil, 0)
	ctx := context.Background()
	work, errStage := service.stageHomeOverlayWithClient(ctx, &config.Config{}, client)
	if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
		t.Fatalf("first stage/commit: %v", errStage)
	}
	local.APIKeys[0] = "mutated-source"
	local.APIKeyPolicies[0].AllowedAuths[0] = "mutated-source.json"
	service.cfg.APIKeys[0] = "mutated-effective"
	service.cfg.APIKeyPolicies[0].AllowedAuths[0] = "mutated-effective.json"
	work, errStage = service.stageHomeOverlayWithClient(ctx, &config.Config{}, client)
	if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
		t.Fatalf("second stage/commit: %v", errStage)
	}
	if !reflect.DeepEqual(service.cfg.APIKeys, []string{"local-L"}) || !reflect.DeepEqual(service.cfg.APIKeyPolicies, []config.APIKeyPolicy{homeSecurityTestPolicy("local-L", "local.json")}) {
		t.Fatalf("local floor shares mutable effective/source state: %+v", service.cfg.SDKConfig)
	}
	reloaded := &config.Config{SDKConfig: config.SDKConfig{
		APIKeys: []string{"local-new-L"}, APIKeyPolicies: []config.APIKeyPolicy{homeSecurityTestPolicy("local-new-L", "reloaded.json")},
	}}
	reloaded.Home.Enabled = true
	if service.commitConfigUpdate(reloaded).cfg == nil {
		t.Fatal("local reload failed")
	}
	work, errStage = service.stageHomeOverlayWithClient(ctx, &config.Config{}, client)
	if errStage != nil || !service.commitHomeConfig(ctx, ctx, 1, work) {
		t.Fatalf("reloaded stage/commit: %v", errStage)
	}
	if !reflect.DeepEqual(service.cfg.APIKeys, []string{"local-new-L"}) || !reflect.DeepEqual(service.cfg.APIKeyPolicies, reloaded.APIKeyPolicies) {
		t.Fatalf("local reload did not replace security baseline: %+v", service.cfg.SDKConfig)
	}
}
