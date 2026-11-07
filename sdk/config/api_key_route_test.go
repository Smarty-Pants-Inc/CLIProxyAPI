package config_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestAPIKeyRoutePublicConfigContract(t *testing.T) {
	hash := sha256.Sum256([]byte("synthetic-sdk-client"))
	digest := hex.EncodeToString(hash[:])
	route := config.APIKeyRoute{KeySHA256: digest, Allow: []string{"GET /v1/models", "/v1/live"}}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{" synthetic-sdk-client "}, APIKeyRoutes: []config.APIKeyRoute{route}}}
	if err := cfg.ValidateAPIKeyRoutes(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateAPIKeyPolicies(); err != nil {
		t.Fatal(err)
	}
	if !route.Matches("GET", "/v1/models/") || route.Matches("POST", "/v1/models") || !route.Matches("POST", "/v1/live") {
		t.Fatal("public alias does not expose route matching semantics")
	}
	body, err := json.Marshal(cfg.SDKConfig)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err = json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	if string(wire["api-key-routes"]) != fmt.Sprintf(`[{"key-sha256":%q,"allow":["GET /v1/models","/v1/live"]}]`, digest) {
		t.Fatalf("public JSON field contract changed: %s", wire["api-key-routes"])
	}
	body, err = json.Marshal(config.SDKConfig{})
	if err != nil || strings.Contains(string(body), "api-key-routes") {
		t.Fatalf("empty routes must be omitted: %v", err)
	}
	loaded, err := config.ParseConfigBytes([]byte(fmt.Sprintf("access: {api-keys: [synthetic-sdk-client], api-key-routes: [{key-sha256: %s, allow: ['GET /v1/models', '/v1/live']}] }\n", digest)))
	if err != nil || len(loaded.APIKeyRoutes) != 1 || !loaded.APIKeyRoutes[0].Matches("GET", "/v1/models") {
		t.Fatalf("SDK parser lost canonical routes: %v", err)
	}
	loaded.APIKeyRoutes[0].Allow = nil
	if err = loaded.ValidateAPIKeyPolicies(); err == nil {
		t.Fatal("existing SDK validator bypassed route validation")
	}
}
