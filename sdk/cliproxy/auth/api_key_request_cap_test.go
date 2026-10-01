package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestAPIKeyPolicyRequestCapAdmissionUTCAndIsolation(t *testing.T) {
	m := NewManager(nil, nil, nil)
	cfg := policyTestConfig("*")
	cap := int64(2)
	cfg.APIKeyPolicies[0].DailyRequestCap = &cap
	cfg.APIKeyPolicies[0].AllowedModels = policyModels("client-model")
	m.SetConfig(cfg)
	now := time.Date(2026, 10, 1, 23, 59, 59, 0, time.UTC)
	m.apiKeyUsage.now = func() time.Time { return now }
	ctx := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
	_, err := m.AdmitClientRequest(ctx, "denied")
	requireControlStatus(t, err, 403)
	var admitted context.Context
	for i := 0; i < 2; i++ {
		admitted, err = m.AdmitClientRequest(ctx, "client-model")
		if err != nil {
			t.Fatal(err)
		}
		// Repeated validation, nested SDK and separate cancellation parent retain one receipt.
		copied := WithClientAPIKeyFromContext(context.Background(), admitted)
		if _, err = m.AdmitClientRequest(copied, "client-model"); err != nil {
			t.Fatal(err)
		}
		if err = m.ValidateClientAuth(copied, &Auth{FileName: "allowed.json"}); err != nil {
			t.Fatal(err)
		}
	}
	_, err = m.AdmitClientRequest(ctx, "client-model")
	requireControlStatus(t, err, 429)
	if err = m.ValidateClientRequest(admitted, "client-model"); err != nil {
		t.Fatal("Nth request rejected itself", err)
	}
	for i := 0; i < 3; i++ {
		if _, err = m.AdmitClientRequest(WithClientAPIKey(context.Background(), "unpolicied"), "any"); err != nil {
			t.Fatal(err)
		}
	}
	m.SetConfig(&internalconfig.Config{}) // Admission cap survives policy removal; no reload reset.
	_, err = m.AdmitClientRequest(ctx, "client-model")
	requireControlStatus(t, err, 429)
	now = now.Add(time.Second)
	if _, err = m.AdmitClientRequest(admitted, "client-model"); err != nil {
		t.Fatal("cross-midnight retry", err)
	}
	if m.apiKeyUsage.requests[cfg.APIKeyPolicies[0].KeySHA256] != 0 {
		t.Fatal("cross-midnight retry charged day two")
	}
	if _, err = m.AdmitClientRequest(ctx, "client-model"); err != nil {
		t.Fatal("UTC rollover", err)
	}
	restarted := NewManager(nil, nil, nil)
	restarted.SetConfig(cfg)
	if _, err = restarted.AdmitClientRequest(ctx, "client-model"); err != nil {
		t.Fatal("restart retained requests", err)
	}
	zero := int64(0)
	cfg.APIKeyPolicies[0].DailyRequestCap = &zero
	restarted.SetConfig(cfg)
	_, err = restarted.AdmitClientRequest(ctx, "client-model")
	requireControlStatus(t, err, 429)
}

func TestAPIKeyPolicyRequestCapConcurrentAdmissions(t *testing.T) {
	m := NewManager(nil, nil, nil)
	cfg := policyTestConfig("*")
	cap := int64(100)
	cfg.APIKeyPolicies[0].DailyRequestCap = &cap
	m.SetConfig(cfg)
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			admitted, err := m.AdmitClientRequest(ctx, "model")
			if err == nil {
				accepted.Add(1)
				if err = m.ValidateClientRequest(admitted, "model"); err != nil {
					t.Errorf("admitted operation denied: %v", err)
				}
			} else {
				requireControlStatus(t, err, 429)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 100 {
		t.Fatalf("accepted=%d", accepted.Load())
	}
	if m.apiKeyUsage.requests[cfg.APIKeyPolicies[0].KeySHA256] != 100 {
		t.Fatal("counter exceeded cap")
	}
}

func TestAPIKeyPolicyRequestCapRetriesConsumeOne(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			cfg := policyTestConfig("allowed-*.json")
			cap := int64(1)
			cfg.APIKeyPolicies[0].DailyRequestCap = &cap
			m.SetConfig(cfg)
			m.SetRetryConfig(2, 0, 0)
			exec := &retryRoundCallExecutor{identifier: "claude"}
			m.RegisterExecutor(exec)
			for _, id := range []string{"a", "b"} {
				registerPolicyAuth(t, m, &Auth{ID: "request-cap-" + id, Provider: "claude", FileName: "allowed-" + id + ".json", Metadata: map[string]any{"disable_cooling": true, "request_retry": 2}})
			}
			ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
			run := func() error {
				req := coreexecutor.Request{Model: "key-policy-model"}
				switch kind {
				case "execute":
					_, err := m.Execute(ctx, []string{"claude"}, req, coreexecutor.Options{})
					return err
				case "count":
					_, err := m.ExecuteCount(ctx, []string{"claude"}, req, coreexecutor.Options{})
					return err
				default:
					_, err := m.ExecuteStream(ctx, []string{"claude"}, req, coreexecutor.Options{Stream: true})
					return err
				}
			}
			err := run()
			if err == nil || isAPIKeyControlError(err) {
				t.Fatalf("first operation refused instead of retried: %v", err)
			}
			if len(exec.ids(kind)) != 6 {
				t.Fatalf("attempts=%v", exec.ids(kind))
			}
			requireControlStatus(t, run(), 429)
			if len(exec.ids(kind)) != 6 || m.apiKeyUsage.requests[cfg.APIKeyPolicies[0].KeySHA256] != 1 {
				t.Fatal("retry spent extra request or capped operation executed")
			}
		})
	}
}

func TestAPIKeyPolicyRequestCapRetainedTurnsAndRawRoutes(t *testing.T) {
	m := NewManager(nil, nil, nil)
	cfg := policyTestConfig("allowed.json")
	cap := int64(2)
	cfg.APIKeyPolicies[0].DailyRequestCap = &cap
	m.SetConfig(cfg)
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	first, err := m.AdmitClientRequest(ctx, "model")
	if err != nil {
		t.Fatal(err)
	}
	selected := &Auth{ID: "request-cap-socket", Provider: "codex", FileName: "allowed.json"}
	bound := m.contextWithClientAuthCheck(first, selected)
	for i := 0; i < 3; i++ {
		if err := coreexecutor.ValidateWebsocketRequest(bound, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := coreexecutor.AdmitWebsocketRequest(bound, ""); err != nil {
		t.Fatal("second retained turn", err)
	}
	_, err = coreexecutor.AdmitWebsocketRequest(bound, "")
	requireControlStatus(t, err, 429)
	for i := 0; i < 3; i++ {
		if err := coreexecutor.ValidateWebsocketRequest(bound, ""); err != nil {
			t.Fatal("admitted writer stopped at request threshold", err)
		}
	}
	// Fresh contexts are exhausted, but raw credential APIs are unavailable even
	// to an admitted context: no receipt can authorize unlimited raw sends.
	if err = m.ValidateMeteredClientRoute(first); statusCodeFromError(err) != 503 {
		t.Fatal("unaccounted live route escaped", err)
	}
	m.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
	if _, err = m.Register(context.Background(), selected); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(first, http.MethodPost, "http://invalid.test", nil)
	if err = m.InjectCredentials(req, selected.ID); statusCodeFromError(err) != 503 {
		t.Fatal("inject escaped", err)
	}
	if err = m.PrepareHttpRequest(first, selected, req); statusCodeFromError(err) != 503 {
		t.Fatal("prepare escaped", err)
	}
	if err = m.PrepareHttpRequest(context.Background(), selected, req); statusCodeFromError(err) != 503 {
		t.Fatal("mixed context erased cap during prepare", err)
	}
	if _, err = m.HttpRequest(first, selected, req); statusCodeFromError(err) != 503 {
		t.Fatal("send escaped", err)
	}
	rejected := dailyRequestCapError()
	if !rejected.IsRequestScoped() {
		t.Fatal("cap not request-scoped")
	}
	selected.Metadata = map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 429, MatchRegexr: []string{".*"}, Action: "continue-and-cooldown"}}}
	if _, ok := matchRequestScopedErrorAction(selected, rejected, cfg); ok {
		t.Fatal("upstream rule overrides request cap")
	}
	if _, retry := m.shouldRetryAfterErrorWithAttempted(first, coreexecutor.Options{}, rejected, 0, []string{"codex"}, "model", time.Second, -1, 10, nil); retry {
		t.Fatal("request cap retried")
	}
}

func TestAPIKeyPolicyCodexOAuthTrainingOffAllowlist(t *testing.T) {
	// Synthetic file names only; this is not verification of any real account.
	for _, identity := range []string{"codex-dev4@smartypants.ai-pro.json", "dev4@smartypants.ai"} {
		t.Run(identity, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
			cfg := policyTestConfig(identity)
			cfg.APIKeyPolicies[0].AllowedProviders = []string{"codex"}
			cfg.APIKeyPolicies[0].AllowedModels = policyModels("gpt-6.1-sol")
			m.SetConfig(cfg)
			allowed := &Auth{ID: fmt.Sprintf("codex-allowed-%s", identity), Provider: "codex", FileName: "codex-dev4@smartypants.ai-pro.json", Metadata: map[string]any{"email": "dev4@smartypants.ai", "access_token": "synthetic-token"}, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth}}
			denied := &Auth{ID: fmt.Sprintf("codex-denied-%s", identity), Provider: "codex", FileName: "codex-dev5@smartypants.ai-pro.json", Metadata: map[string]any{"email": "dev5@smartypants.ai", "access_token": "synthetic-other-token"}, Attributes: map[string]string{AttributeAuthKind: AuthKindOAuth, "priority": "100"}}
			for _, a := range []*Auth{allowed, denied} {
				if _, err := m.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
				id := a.ID
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			ctx := m.WithClientRequest(WithClientAPIKey(context.Background(), policyTestClientKey), "gpt-6.1-sol")
			for i := 0; i < 3; i++ {
				selected, err := m.SelectAuthByKind(ctx, "codex", "gpt-6.1-sol", AuthKindOAuth, coreexecutor.Options{})
				if err != nil || selected == nil || selected.ID != allowed.ID {
					t.Fatalf("OAuth select=%v %v", selected, err)
				}
			}
			requirePolicyDenied(t, m.ValidateClientAuth(ctx, denied))
			allowed.Disabled = true
			if _, err := m.Update(context.Background(), allowed); err != nil {
				t.Fatal(err)
			}
			selected, err := m.SelectAuthByKind(ctx, "codex", "gpt-6.1-sol", AuthKindOAuth, coreexecutor.Options{})
			if selected != nil || err == nil || (statusCodeFromError(err) != 503 && statusCodeFromError(err) != 429) {
				t.Fatalf("exhausted OAuth fell back: %v %v", selected, err)
			}
			selected, err = m.SelectAuthByKind(WithClientAPIKey(context.Background(), "unpolicied"), "codex", "gpt-6.1-sol", AuthKindOAuth, coreexecutor.Options{})
			if err != nil || selected == nil || selected.ID != denied.ID {
				t.Fatal("unpolicied Codex changed", err)
			}
		})
	}
}
