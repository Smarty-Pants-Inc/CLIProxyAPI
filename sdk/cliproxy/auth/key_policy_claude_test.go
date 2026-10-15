package auth

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A Claude send carries exactly one credential header with exactly one value.
func TestKeyPolicyClaudeCredentialHeader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers [][2]string
		ok      bool
	}{
		{name: "x-api-key", headers: [][2]string{{"X-Api-Key", "A-token"}}, ok: true},
		{name: "bearer", headers: [][2]string{{"Authorization", "Bearer A-token"}}, ok: true},
		{name: "duplicate x-api-key", headers: [][2]string{{"X-Api-Key", "A-token"}, {"X-Api-Key", "A-token"}}},
		{name: "duplicate bearer", headers: [][2]string{{"Authorization", "Bearer A-token"}, {"Authorization", "Bearer A-token"}}},
		{name: "x-api-key plus other", headers: [][2]string{{"X-Api-Key", "A-token"}, {"X-Api-Key", "B-token"}}},
		{name: "both headers", headers: [][2]string{{"X-Api-Key", "A-token"}, {"Authorization", "Bearer A-token"}}},
		{name: "wrong token", headers: [][2]string{{"X-Api-Key", "B-token"}}},
		{name: "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			models := []string{"claude-model"}
			policy := config.APIKeyPolicy{KeySHA256: keyDigest("key"), AllowedAuths: []string{"A"}, AllowedModels: &models, DailyRequestCap: policyInt(10), DailyTokenCap: policyInt(100)}
			m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{policy}}})
			_, _ = m.Register(context.Background(), &Auth{ID: "A", Provider: "claude", Status: StatusActive, Attributes: map[string]string{"api_key": "A-token"}})
			m.RegisterExecutor(&countingRefreshExecutor{id: "claude"})
			registry.GetGlobalRegistry().RegisterClient("A", "claude", []*registry.ModelInfo{{ID: "claude-model"}})
			defer registry.GetGlobalRegistry().UnregisterClient("A")
			ctx, done, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{policy}, "claude-model")
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			if _, _, err := KeyPolicyFromContext(ctx).selectExecutor(ex.Request{Model: "claude-model"}, ex.Options{}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "http://example/v1/messages?beta=true", strings.NewReader(`{"model":"claude-model"}`)).WithContext(ctx)
			for _, h := range tc.headers {
				req.Header.Add(h[0], h[1])
			}
			if err := CheckKeyPolicySend(req); (err == nil) != tc.ok {
				t.Fatalf("CheckKeyPolicySend err=%v want ok=%t", err, tc.ok)
			}
		})
	}
}
