package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Daily request receipts and upstream attempt budgets are different boundaries:
// nested execution keeps both; a new retained turn renews both, not the floor.
func TestAPIKeySingleAttemptRequestCapAndAdmissionFloor(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			t.Cleanup(m.StopAutoRefresh)
			cfg := policyTestConfig("allowed-*.json")
			cap := int64(1)
			cfg.APIKeyPolicies[0].DailyRequestCap = &cap
			cfg.APIKeyPolicies[0].SingleAttempt = true
			cfg.APIKeyPolicies[0].AllowedModels = policyModels("key-policy-model", "alternate-model")
			m.SetConfig(cfg)
			m.SetRetryConfig(2, 0, 0)
			failure := &coreexecutor.ClientUpstreamError{Status: http.StatusServiceUnavailable, Body: []byte("synthetic upstream failure"), Terminal: true}
			exec := &singleAttemptTestExecutor{retryRoundCallExecutor: retryRoundCallExecutor{identifier: "claude"}, failure: failure}
			m.RegisterExecutor(exec)
			for _, id := range []string{"a", "b"} {
				registerPolicyAuth(t, m, &Auth{ID: "merge-floor-" + id, Provider: "claude", FileName: "allowed-" + id + ".json", Metadata: map[string]any{"request_retry": 2, "disable_cooling": true}})
			}
			principal := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
			admitted, err := m.AdmitClientRequest(principal, "key-policy-model")
			if err != nil {
				t.Fatal(err)
			}
			m.SetConfig(&internalconfig.Config{})
			copied := WithClientAPIKeyFromContext(context.Background(), admitted)
			if !m.SingleAttemptClient(copied) || !coreexecutor.ClientSingleAttempt(copied) {
				t.Fatal("policy removal/context copy erased single-attempt floor")
			}
			// The alternate name is allowlisted, but cannot replace this operation's
			// original model through plugin metadata or nested execution.
			_, err = m.AdmitClientRequest(copied, "alternate-model")
			requireControlStatus(t, err, http.StatusForbidden)
			_, err = m.Execute(copied, []string{"claude"}, coreexecutor.Request{Model: "key-policy-model"}, coreexecutor.Options{Metadata: map[string]any{coreexecutor.RequestedModelMetadataKey: "alternate-model"}})
			requireControlStatus(t, err, http.StatusForbidden)
			if len(exec.executeIDs) != 0 {
				t.Fatal("nested model substitution reached executor")
			}
			if err = invokeSingleAttemptTest(m, copied, kind); !errors.Is(err, failure) {
				t.Fatalf("error=%v, want original single-attempt upstream error", err)
			}
			if calls := exec.ids(kind); len(calls) != 1 {
				t.Fatalf("single attempt rotated/retried: %v", calls)
			}
			_, err = m.AdmitClientRequest(principal, "key-policy-model")
			requireControlStatus(t, err, http.StatusTooManyRequests)
			if got := m.apiKeyUsage.requests[cfg.APIKeyPolicies[0].KeySHA256]; got != 1 {
				t.Fatalf("nested execution changed logical request count: %d", got)
			}
		})
	}
}

func TestAPIKeySingleAttemptRetainedTurnCapAndExactModel(t *testing.T) {
	m := NewManager(nil, nil, nil)
	cfg := policyTestConfig("allowed.json")
	cap := int64(2)
	cfg.APIKeyPolicies[0].DailyRequestCap = &cap
	cfg.APIKeyPolicies[0].SingleAttempt = true
	cfg.APIKeyPolicies[0].AllowedModels = policyModels("first-model", "next-model")
	m.SetConfig(cfg)
	principal := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
	first, err := m.AdmitClientRequest(principal, "first-model")
	if err != nil {
		t.Fatal(err)
	}
	if err = coreexecutor.ClaimClientUpstreamAttempt(first); err != nil {
		t.Fatal(err)
	}
	copied := WithClientAPIKeyFromContext(context.Background(), first)
	if err = coreexecutor.ClaimClientUpstreamAttempt(copied); err == nil {
		t.Fatal("new cancellation parent refunded upstream attempt")
	}
	if err = m.ValidateClientRequest(copied, "next-model"); statusCodeFromError(err) != http.StatusForbidden {
		t.Fatal("in-flight turn changed exact model", err)
	}
	bound := m.contextWithClientAuthCheck(first, &Auth{ID: "merge-retained", Provider: "codex", FileName: "allowed.json"})
	m.SetConfig(&internalconfig.Config{})
	next, err := coreexecutor.AdmitWebsocketRequest(bound, "next-model")
	if err != nil {
		t.Fatal("second retained turn denied", err)
	}
	if coreexecutor.ClientExecutionModel(next) != "next-model" || !coreexecutor.ClientSingleAttempt(next) {
		t.Fatal("fresh retained turn lost its exact model/single-attempt floor")
	}
	if err = coreexecutor.ValidateClientWireModel(next, []byte(`{"model":"next-model"}`), false); err != nil {
		t.Fatal(err)
	}
	if err = coreexecutor.ValidateClientWireModel(next, []byte(`{"model":"first-model"}`), false); err == nil {
		t.Fatal("retained turn accepted previous wire model")
	}
	if err = coreexecutor.ClaimClientUpstreamAttempt(next); err != nil {
		t.Fatal("second retained turn reused first attempt budget", err)
	}
	if err = coreexecutor.ClaimClientUpstreamAttempt(next); err == nil {
		t.Fatal("second retained turn retried")
	}
	if _, err = coreexecutor.AdmitWebsocketRequest(bound, "next-model"); statusCodeFromError(err) != http.StatusTooManyRequests {
		t.Fatal("third retained turn escaped immutable daily cap", err)
	}
	if got := m.apiKeyUsage.requests[cfg.APIKeyPolicies[0].KeySHA256]; got != 2 {
		t.Fatalf("retained request count=%d, want 2", got)
	}
}
