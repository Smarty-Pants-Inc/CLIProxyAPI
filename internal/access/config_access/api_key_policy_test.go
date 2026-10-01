package configaccess

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyPolicyAuthenticationSnapshotSurvivesReload(t *testing.T) {
	cfg := config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", AllowedAuths: []string{"verified.json"}}}}
	old := newProvider("test", []string{"synthetic-key"}, cfg.APIKeyPolicies...)
	cfg.APIKeyPolicies[0].AllowedAuths[0] = "denied.json"
	replacement := newProvider("test", []string{"synthetic-key"})
	request := httptest.NewRequest("POST", "/v1/responses", nil)
	request.Header.Set("Authorization", "Bearer synthetic-key")
	result, err := old.Authenticate(context.Background(), request)
	if err != nil || result == nil || len(result.APIKeyPolicies) != 1 || result.APIKeyPolicies[0].AllowedAuths[0] != "verified.json" {
		t.Fatal("in-flight authentication lost immutable old policy snapshot")
	}
	current, err := replacement.Authenticate(context.Background(), request)
	if err != nil || current == nil || len(current.APIKeyPolicies) != 0 {
		t.Fatal("new unpolicied admission changed")
	}
}
