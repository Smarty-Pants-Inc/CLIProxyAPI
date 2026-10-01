package auth

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func policyModels(patterns ...string) *[]string { return &patterns }

type policyCountingSelector struct{ calls int }

func (s *policyCountingSelector) Pick(context.Context, string, string, coreexecutor.Options, []*Auth) (*Auth, error) {
	s.calls++
	return nil, errors.New("selector should not run")
}

func requireControlStatus(t *testing.T, err error, status int) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.HTTPStatus != status {
		t.Fatalf("error=%v; want %d", err, status)
	}
}

func TestAPIKeyPolicyClientControlsNeverCoolSharedCredentials(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	selected := &Auth{ID: "client-control-shared", Provider: "codex"}
	if _, err := manager.Register(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	for _, rejected := range []*Error{
		{Code: "api_key_model_forbidden", HTTPStatus: 403},
		{Code: "api_key_daily_token_cap", HTTPStatus: 429},
	} {
		if !rejected.IsRequestScoped() {
			t.Fatal("client-local refusal is not request scoped")
		}
		result := resultErrorFromError(rejected)
		if !shouldSkipCredentialCooldown(result) {
			t.Fatal("client policy would penalize shared credential")
		}
		manager.MarkResult(context.Background(), Result{AuthID: selected.ID, Provider: selected.Provider, Model: "model", Error: result})
		current, _ := manager.GetByID(selected.ID)
		if state := current.ModelStates["model"]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
			t.Fatal("client-local refusal cooled shared auth")
		}
	}
}

func TestAPIKeyPolicyClientControlsIgnoreUpstreamErrorRules(t *testing.T) {
	for _, action := range []string{"stop-and-cooldown", "continue-and-cooldown"} {
		t.Run(action, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := policyTestConfig("*")
			cap := int64(5)
			cfg.APIKeyPolicies[0].DailyTokenCap = &cap
			manager.SetConfig(cfg)
			selected := &Auth{ID: "client-rule-" + action, FileName: "verified.json", Provider: "claude", Metadata: map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 429, Match: []string{"token"}, MatchRegexr: []string{".*"}, Action: action}}}}
			registerPolicyAuth(t, manager, selected)
			usage := coreusage.NewManager(0)
			t.Cleanup(usage.Stop)
			calls := 0
			manager.RegisterExecutor(&mockCustomErrorExecutor{identifier: "claude", executeFn: func(ctx context.Context, selected *Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
				calls++
				usage.Publish(ctx, coreusage.Record{Detail: coreusage.Detail{InputTokens: 5}})
				return coreexecutor.Response{}, manager.ValidateClientRequest(ctx, req.Model)
			}})
			ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
			_, err := manager.Execute(ctx, []string{"claude"}, coreexecutor.Request{Model: "key-policy-model"}, coreexecutor.Options{})
			requireControlStatus(t, err, 429)
			if calls != 1 {
				t.Fatal("upstream override retried client cap refusal")
			}
			if override, ok := matchRequestScopedErrorAction(selected, err, cfg); ok || override != "" {
				t.Fatal("upstream error rule matched client policy")
			}
			current, _ := manager.GetByID(selected.ID)
			if state := current.ModelStates["key-policy-model"]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
				t.Fatal("upstream error-action override cooled shared credential")
			}
		})
	}
}

func TestAPIKeyPolicyModelsDeniedBeforeSelection(t *testing.T) {
	for _, home := range []bool{false, true} {
		t.Run(fmt.Sprintf("home=%v", home), func(t *testing.T) {
			selector := &policyCountingSelector{}
			manager := NewManager(nil, selector, nil)
			cfg := policyTestConfig("*")
			cfg.APIKeyPolicies[0].AllowedModels = policyModels("key-policy-*")
			cfg.Home.Enabled = home
			manager.SetConfig(cfg)
			ctx := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
			request := coreexecutor.Request{Model: "denied-model"}
			_, err := manager.Execute(ctx, []string{"claude"}, request, coreexecutor.Options{})
			requireControlStatus(t, err, http.StatusForbidden)
			_, err = manager.ExecuteCount(ctx, []string{"claude"}, request, coreexecutor.Options{})
			requireControlStatus(t, err, http.StatusForbidden)
			_, err = manager.ExecuteStream(ctx, []string{"claude"}, request, coreexecutor.Options{})
			requireControlStatus(t, err, http.StatusForbidden)
			if selector.calls != 0 {
				t.Fatal("credential selection ran for denied model")
			}
			if err := manager.ValidateClientRequest(ctx, "key-policy-allowed"); err != nil {
				t.Fatal(err)
			}
			if err := manager.ValidateClientRequest(ctx, "KEY-POLICY-allowed"); err == nil {
				t.Fatal("glob became case insensitive")
			}
			if err := manager.ValidateClientRequest(WithClientAPIKey(context.Background(), "unpolicied-key"), "denied-model"); err != nil {
				t.Fatal("unpolicied model changed")
			}
			cfg.APIKeyPolicies[0].AllowedModels = policyModels()
			manager.SetConfig(cfg)
			requireControlStatus(t, manager.ValidateClientRequest(ctx, "key-policy-allowed"), 403)
		})
	}
}

func TestAPIKeyPolicyDailyCapFromSynchronousUsageAndUTCReset(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := policyTestConfig("*")
	cap := int64(10)
	cfg.APIKeyPolicies[0].DailyTokenCap = &cap
	manager.SetConfig(cfg)
	now := time.Date(2026, 10, 1, 23, 59, 59, 0, time.UTC)
	manager.apiKeyUsage.now = func() time.Time { return now }
	ctx := manager.WithClientRequest(WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies), "key-policy-model")
	usage := coreusage.NewManager(0)
	t.Cleanup(usage.Stop)
	// Accounting is synchronous even with no plugins/Redis/statistics consumer.
	record := coreusage.Record{RequestID: "attempt-one", APIKey: "wrong-mutable-usage-key", RequestedAt: now.Add(-time.Hour), Detail: coreusage.Detail{InputTokens: 3, OutputTokens: 2, ReasoningTokens: 99, TotalTokens: 500}}
	usage.Publish(ctx, record)
	if err := manager.ValidateClientRequest(ctx, "key-policy-model"); err != nil {
		t.Fatal(err)
	}
	usage.Publish(ctx, record) // Same execution must not double-count.
	if err := manager.ValidateClientRequest(ctx, "key-policy-model"); err != nil {
		t.Fatal("duplicate record charged twice")
	}
	record.RequestID = "attempt-two"
	record.Failed = true
	usage.Publish(ctx, record)
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "key-policy-model"), 429)
	if err := manager.ValidateClientRequest(WithClientAPIKey(context.Background(), "unpolicied-key"), "any"); err != nil {
		t.Fatal("other key shared cap")
	}
	// Reload does not reset accounting or an already-admitted cap.
	manager.SetConfig(&internalconfig.Config{})
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "key-policy-model"), 429)
	now = now.Add(time.Second) // 00:00 UTC, deterministic with no sleeping.
	if err := manager.ValidateClientRequest(ctx, "key-policy-model"); err != nil {
		t.Fatal("UTC midnight did not clear cap")
	}
	// RequestedAt is yesterday: charge the day usage is published, not queued sink time.
	usage.Publish(ctx, record)
	usage.Publish(ctx, coreusage.Record{RequestID: "late-day-two", Detail: coreusage.Detail{InputTokens: 5}})
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "key-policy-model"), 429)
	restarted := NewManager(nil, nil, nil)
	restarted.SetConfig(cfg)
	if err := restarted.ValidateClientRequest(ctx, "key-policy-model"); err != nil {
		t.Fatal("in-memory counter survived restart")
	}
}

func TestAPIKeyPolicyDailyCapIncludesUsageBeforePolicyActivation(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	ctx := manager.WithClientRequest(WithClientAPIKey(context.Background(), policyTestClientKey), "model")
	usage := coreusage.NewManager(0)
	t.Cleanup(usage.Stop)
	usage.Publish(ctx, coreusage.Record{RequestID: "before-policy", Detail: coreusage.Detail{InputTokens: 3, OutputTokens: 2}})
	if err := manager.ValidateClientRequest(ctx, "model"); err != nil {
		t.Fatal("unpolicied request changed")
	}
	cfg := policyTestConfig("*")
	cap := int64(5)
	cfg.APIKeyPolicies[0].DailyTokenCap = &cap
	manager.SetConfig(cfg)
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "model"), 429)
}

func TestAPIKeyPolicyDailyCapConcurrentUsageAndOverflow(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := policyTestConfig("*")
	cap := int64(100)
	cfg.APIKeyPolicies[0].DailyTokenCap = &cap
	manager.SetConfig(cfg)
	ctx := manager.WithClientRequest(WithClientAPIKey(context.Background(), policyTestClientKey), "model")
	usage := coreusage.NewManager(0)
	t.Cleanup(usage.Stop)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			usage.Publish(ctx, coreusage.Record{RequestID: fmt.Sprintf("record-%d", i), Detail: coreusage.Detail{InputTokens: 1}})
		}(i)
	}
	wg.Wait()
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "model"), 429)
	manager.apiKeyUsage.mu.Lock()
	total := manager.apiKeyUsage.tokens[cfg.APIKeyPolicies[0].KeySHA256]
	manager.apiKeyUsage.mu.Unlock()
	if total != 100 {
		t.Fatalf("concurrent total=%d", total)
	}
	usage.Publish(ctx, coreusage.Record{RequestID: "overflow", Detail: coreusage.Detail{InputTokens: math.MaxInt64, OutputTokens: math.MaxInt64}})
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "model"), 429)
	usage.Publish(ctx, coreusage.Record{RequestID: "negative", Detail: coreusage.Detail{InputTokens: -100, OutputTokens: -100}})
	requireControlStatus(t, manager.ValidateClientRequest(ctx, "model"), 429)
}

func TestAPIKeyPolicyAliasAndRetainedModelControls(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := policyTestConfig("verified.json")
	cfg.APIKeyPolicies[0].AllowedModels = policyModels("client-alias")
	manager.SetConfig(cfg)
	ctx := manager.WithClientRequest(WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies), "client-alias")
	selected := &Auth{ID: "policy-socket", FileName: "verified.json"}
	bound := manager.contextWithClientAuthCheck(ctx, selected)
	if err := coreexecutor.ValidateWebsocketRequest(bound, ""); err != nil {
		t.Fatal("inherited model checked as upstream alias")
	}
	requireControlStatus(t, coreexecutor.ValidateWebsocketRequest(bound, "upstream-name"), 403)
	_, _, _, err := manager.pickNextMixed(ctx, []string{"claude"}, "upstream-name", coreexecutor.Options{Metadata: map[string]any{coreexecutor.RequestedModelMetadataKey: "denied-client-alias"}}, nil)
	requireControlStatus(t, err, 403)
	requireControlStatus(t, preferredExecutionAttemptError(err, errors.New("old upstream error")), 403)
	if _, retry := manager.shouldRetryAfterErrorWithAttempted(ctx, coreexecutor.Options{}, err, 0, []string{"claude"}, "upstream-name", time.Second, -1, 10, nil); retry {
		t.Fatal("model refusal retried credential fallback")
	}
	cap := int64(0)
	cfg.APIKeyPolicies[0].DailyTokenCap = &cap
	manager.SetConfig(cfg)
	requireControlStatus(t, coreexecutor.ValidateWebsocketRequest(bound, ""), 429)
}
