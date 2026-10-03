package configaccess

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

func TestR3AccessProviderReloadFreezesPolicy(t *testing.T) {
	for _, change := range []string{"added", "removed", "changed"} {
		t.Run(change, func(t *testing.T) {
			Register(nil)
			t.Cleanup(func() { Register(nil) })
			key := t.Name()
			b := sha256.Sum256([]byte(key))
			p := config.APIKeyPolicy{KeySHA256: hex.EncodeToString(b[:]), AllowedAuths: []string{"A"}}
			old := &config.SDKConfig{APIKeys: []string{key}}
			if change != "added" {
				old.APIKeyPolicies = []config.APIKeyPolicy{p}
			}
			Register(old)
			next := &config.SDKConfig{APIKeys: []string{key}}
			if change != "removed" {
				next.APIKeyPolicies = []config.APIKeyPolicy{p}
				if change == "changed" {
					next.APIKeyPolicies[0].AllowedAuths = []string{"B"}
				}
			}
			Register(next)
			req := httptest.NewRequest("GET", "/v1/realtime", nil)
			req.Header.Set("Authorization", "Bearer "+key)
			var result *sdkaccess.Result
			for _, provider := range sdkaccess.RegisteredProviders() {
				if provider.Identifier() == sdkaccess.DefaultAccessProviderName {
					result, _ = provider.Authenticate(context.Background(), req)
				}
			}
			if result == nil {
				t.Fatal("no authenticated provider")
			}
			var got []config.APIKeyPolicy
			if result.Metadata["key_policy"] != "" {
				if err := json.Unmarshal([]byte(result.Metadata["key_policy"]), &got); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(got, old.APIKeyPolicies) {
				t.Fatalf("access snapshot changed: got=%+v want=%+v", got, old.APIKeyPolicies)
			}
			newKey := key + "-new"
			b = sha256.Sum256([]byte(newKey))
			next.APIKeys = append(next.APIKeys, newKey)
			next.APIKeyPolicies = append(next.APIKeyPolicies, config.APIKeyPolicy{KeySHA256: hex.EncodeToString(b[:])})
			Register(next)
			req.Header.Set("Authorization", "Bearer "+newKey)
			for _, provider := range sdkaccess.RegisteredProviders() {
				if provider.Identifier() == sdkaccess.DefaultAccessProviderName {
					result, _ = provider.Authenticate(context.Background(), req)
				}
			}
			if result == nil || result.Metadata["key_policy"] == "" {
				t.Fatal("new policied key missing access snapshot")
			}
		})
	}
}
