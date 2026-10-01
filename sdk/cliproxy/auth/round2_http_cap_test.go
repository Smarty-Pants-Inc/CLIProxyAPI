package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestRound2Finding11CappedHTTPAdmissionFailsClosed(t *testing.T) {
	for _, operation := range []string{"prepare", "inject", "send"} {
		t.Run(operation, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := policyTestConfig("allowed.json")
			cap := int64(5)
			cfg.APIKeyPolicies[0].DailyTokenCap = &cap
			manager.SetConfig(cfg)
			executor := &round2PrepareExecutor{}
			manager.RegisterExecutor(executor)
			allowed := &Auth{ID: "capped-http", Provider: "antigravity", FileName: "allowed.json"}
			registerPolicyAuth(t, manager, allowed)
			source := manager.WithClientRequest(WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies), "key-policy-model")
			// Relax current config. The immutable admission floor still forbids a
			// raw HTTP composition with no canonical token accounting boundary.
			manager.SetConfig(&internalconfig.Config{})
			req, _ := http.NewRequestWithContext(source, http.MethodGet, "http://example.invalid", nil)
			var err error
			switch operation {
			case "prepare":
				err = manager.PrepareHttpRequest(context.Background(), allowed, req)
			case "inject":
				err = manager.InjectCredentials(req, allowed.ID)
			case "send":
				_, err = manager.HttpRequest(context.Background(), allowed, req)
			}
			var refusal *Error
			if !errors.As(err, &refusal) || refusal.Code != "api_key_usage_unavailable" || refusal.HTTPStatus != http.StatusServiceUnavailable {
				t.Errorf("capped raw HTTP %s=%v; want unmetered-route refusal", operation, err)
			}
			if req.Header.Get("Authorization") != "" || executor.httpCalls != 0 {
				t.Error("capped raw HTTP injected or dispatched")
			}
		})
	}
}
