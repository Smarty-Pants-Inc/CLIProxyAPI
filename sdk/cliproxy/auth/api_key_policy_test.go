package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const policyTestClientKey = "synthetic-restricted-client"

func policyTestConfig(patterns ...string) *internalconfig.Config {
	digest := sha256.Sum256([]byte(policyTestClientKey))
	return &internalconfig.Config{SDKConfig: internalconfig.SDKConfig{
		APIKeyPolicies: []internalconfig.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: patterns}},
	}}
}

func registerPolicyAuth(t *testing.T, manager *Manager, auth *Auth) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "key-policy-model"}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
}

func requirePolicyDenied(t *testing.T, err error) {
	t.Helper()
	var policyErr *Error
	if !errors.As(err, &policyErr) || policyErr.Code != "api_key_policy_unavailable" || policyErr.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("error = %v, want explicit API-key-policy 503", err)
	}
}

func TestAPIKeyPolicyAdmissionFloorAndBoundSocket(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := policyTestConfig("verified.json")
	manager.SetConfig(cfg)
	ctx := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
	// Removing a policy cannot unrestrict a request admitted with it.
	manager.SetConfig(&internalconfig.Config{})
	requirePolicyDenied(t, manager.ValidateClientAuth(ctx, &Auth{FileName: "denied.json"}))
	allowed := &Auth{ID: "bound-policy-socket", FileName: "verified.json"}
	if err := manager.ValidateClientAuth(ctx, allowed); err != nil {
		t.Fatal(err)
	}
	boundCtx := manager.contextWithClientAuthCheck(ctx, allowed)
	// Replacing the same ID cannot rewrite the socket's actual dial credential.
	allowed.FileName = "replacement.json"
	manager.SetConfig(policyTestConfig("replacement.json"))
	if cliproxyexecutor.WebsocketAuthEnabled(boundCtx, allowed.ID) {
		t.Fatal("retained socket blessed by replacement auth identity")
	}
	// Current configuration is also enforced against the admission snapshot.
	requirePolicyDenied(t, manager.ValidateClientAuth(ctx, allowed))
}

func TestAPIKeyPolicySelection(t *testing.T) {
	for _, strategy := range []struct {
		name        string
		newSelector func() Selector
	}{
		{"round-robin", func() Selector { return &RoundRobinSelector{} }},
		{"weighted", func() Selector { return &WeightedRoundRobinSelector{} }},
		{"fill-first", func() Selector { return &FillFirstSelector{} }},
		{"session-affinity", func() Selector { return NewSessionAffinitySelector(&RoundRobinSelector{}) }},
	} {
		for _, mixed := range []bool{false, true} {
			t.Run(strategy.name+map[bool]string{false: "/single", true: "/mixed"}[mixed], func(t *testing.T) {
				manager := NewManager(nil, strategy.newSelector(), nil)
				t.Cleanup(manager.StopAutoRefresh)
				manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
				manager.RegisterExecutor(schedulerTestExecutor{provider: "codex"})
				cfg := policyTestConfig("claude-*-verified.json")
				cfg.APIKeyPolicies[0].AllowedProviders = []string{"claude"}
				manager.SetConfig(cfg)
				for _, a := range []*Auth{
					{ID: "policy-denied", Provider: "claude", FileName: "claude-training-on.json", Attributes: map[string]string{"priority": "100", AttributeWeight: "100"}},
					{ID: "policy-wrong-provider", Provider: "codex", FileName: "claude-other-verified.json", Attributes: map[string]string{"priority": "200", AttributeWeight: "100"}},
					{ID: "policy-allowed", Provider: "claude", FileName: "/synthetic/auth-dir/claude-one-verified.json", Attributes: map[string]string{AttributeWeight: "1"}},
				} {
					registerPolicyAuth(t, manager, a)
				}
				ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
				for i := 0; i < 3; i++ {
					var selected *Auth
					var err error
					if mixed {
						selected, _, _, err = manager.pickNextMixed(ctx, []string{"claude", "codex"}, "key-policy-model", cliproxyexecutor.Options{}, nil)
					} else {
						selected, _, err = manager.pickNext(ctx, "claude", "key-policy-model", cliproxyexecutor.Options{}, nil)
					}
					if err != nil || selected == nil || selected.ID != "policy-allowed" {
						t.Fatalf("pick = %v, %v; want allowed only", selected, err)
					}
				}
				selected, err := manager.SelectAuth(ctx, "claude", "key-policy-model", cliproxyexecutor.Options{})
				if err != nil || selected.ID != "policy-allowed" {
					t.Fatalf("legacy selection = %v, %v", selected, err)
				}
				// A different authenticated key must keep the old highest-priority choice.
				selected, err = manager.SelectAuth(WithClientAPIKey(context.Background(), "unpolicied-key"), "claude", "key-policy-model", cliproxyexecutor.Options{})
				if err != nil || selected.ID != "policy-denied" {
					t.Fatalf("unpolicied selection = %v, %v", selected, err)
				}
			})
		}
	}
}

type policyRogueSelector struct{ denied *Auth }

func (s policyRogueSelector) Pick(context.Context, string, string, cliproxyexecutor.Options, []*Auth) (*Auth, error) {
	return s.denied, nil
}

func TestAPIKeyPolicyRejectsSelectorOutsideCandidates(t *testing.T) {
	denied := &Auth{ID: "rogue-denied", Provider: "claude", FileName: "denied.json"}
	manager := NewManager(nil, policyRogueSelector{denied: denied}, nil)
	manager.SetConfig(policyTestConfig("allowed.json"))
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	registerPolicyAuth(t, manager, &Auth{ID: "rogue-allowed", Provider: "claude", FileName: "allowed.json"})
	selected, err := manager.SelectAuth(WithClientAPIKey(context.Background(), policyTestClientKey), "claude", "key-policy-model", cliproxyexecutor.Options{})
	if selected != nil {
		t.Fatal("selector escaped filtered candidate set")
	}
	requirePolicyDenied(t, err)
}

func TestAPIKeyPolicyIdentityMatching(t *testing.T) {
	policy := internalconfig.APIKeyPolicy{AllowedAuths: []string{"verified*@example.com"}}
	for _, tc := range []struct {
		name    string
		auth    *Auth
		allowed bool
	}{
		{"metadata-email", &Auth{Metadata: map[string]any{"email": "verified1@example.com"}}, true},
		{"attribute-email", &Auth{Attributes: map[string]string{"email": "verified2@example.com"}}, true},
		{"id-is-not-name", &Auth{ID: "verified1@example.com"}, false},
		{"label-is-not-name", &Auth{Label: "verified1@example.com"}, false},
		{"wrong-email", &Auth{Metadata: map[string]any{"email": "denied@example.com"}}, false},
		{"case-sensitive", &Auth{Metadata: map[string]any{"email": "VERIFIED1@example.com"}}, false},
		{"absent", &Auth{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiKeyPolicyAllows(policy, tc.auth); got != tc.allowed {
				t.Fatalf("allowed = %v", got)
			}
		})
	}
	if apiKeyPolicyAllows(internalconfig.APIKeyPolicy{}, &Auth{FileName: "any.json"}) {
		t.Fatal("empty allowlist allowed a credential")
	}
	if apiKeyPolicyAllows(internalconfig.APIKeyPolicy{AllowedAuths: []string{"["}}, &Auth{FileName: "any.json"}) {
		t.Fatal("malformed pattern failed open")
	}
}

func TestAPIKeyPolicyPluginSchedulerDelegateAndPinnedDenial(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	manager.SetConfig(policyTestConfig("allowed.json"))
	for _, a := range []*Auth{{ID: "plugin-allowed", Provider: "claude", FileName: "allowed.json"}, {ID: "plugin-denied", Provider: "claude", FileName: "denied.json", Attributes: map[string]string{"priority": "100"}}} {
		registerPolicyAuth(t, manager, a)
	}
	scheduler := &fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, DelegateBuiltin: pluginapi.SchedulerBuiltinRoundRobin}}
	manager.SetPluginScheduler(scheduler)
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	selected, err := manager.SelectAuth(ctx, "claude", "key-policy-model", cliproxyexecutor.Options{})
	if err != nil || selected.ID != "plugin-allowed" {
		t.Fatalf("plugin delegate = %v, %v", selected, err)
	}
	if len(scheduler.requests) != 1 || len(scheduler.requests[0].Candidates) != 1 || scheduler.requests[0].Candidates[0].ID != "plugin-allowed" {
		t.Fatalf("plugin received denied candidates: %v", scheduler.requests)
	}
	selected, err = manager.SelectAuth(ctx, "claude", "key-policy-model", cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: "plugin-denied"}})
	if selected != nil {
		t.Fatal("denied pinned credential selected")
	}
	requirePolicyDenied(t, err)
}

func TestAPIKeyPolicyExhaustionNeverFallsBack(t *testing.T) {
	for _, cooling := range []bool{false, true} {
		for _, kind := range []string{"execute", "count", "stream"} {
			t.Run(kind+map[bool]string{false: "/disabled", true: "/cooldown"}[cooling], func(t *testing.T) {
				manager := NewManager(nil, nil, nil)
				manager.SetConfig(policyTestConfig("allowed.json"))
				executor := &retryRoundCallExecutor{identifier: "claude"}
				manager.RegisterExecutor(executor)
				allowed := &Auth{ID: "exhausted-allowed", Provider: "claude", FileName: "allowed.json", Disabled: !cooling}
				if cooling {
					allowed.Unavailable = true
					allowed.NextRetryAfter = time.Now().Add(time.Hour)
					allowed.Quota = QuotaState{Exceeded: true}
				}
				registerPolicyAuth(t, manager, allowed)
				registerPolicyAuth(t, manager, &Auth{ID: "exhausted-denied", Provider: "claude", FileName: "denied.json"})
				ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
				req := cliproxyexecutor.Request{Model: "key-policy-model", Payload: []byte("client content")}
				var err error
				switch kind {
				case "execute":
					_, err = manager.Execute(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
				case "count":
					_, err = manager.ExecuteCount(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
				case "stream":
					_, err = manager.ExecuteStream(ctx, []string{"claude"}, req, cliproxyexecutor.Options{Stream: true})
				}
				if status := statusCodeFromError(err); status != 503 && status != 429 {
					t.Fatalf("error = %v (status %d), want 503/429", err, status)
				}
				if calls := executor.ids(kind); len(calls) != 0 {
					t.Fatalf("exhaustion escaped allowlist: %v", calls)
				}
			})
		}
	}
}

func TestAPIKeyPolicyRetriesStayInSet(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(policyTestConfig("allowed-*.json"))
			manager.SetRetryConfig(2, 0, 0)
			executor := &retryRoundCallExecutor{identifier: "claude"}
			manager.RegisterExecutor(executor)
			for _, a := range []*Auth{
				{ID: "retry-policy-a", Provider: "claude", FileName: "allowed-a.json", Metadata: map[string]any{"disable_cooling": true, "request_retry": 2}},
				{ID: "retry-policy-b", Provider: "claude", FileName: "allowed-b.json", Metadata: map[string]any{"disable_cooling": true, "request_retry": 2}},
				{ID: "retry-policy-denied", Provider: "claude", FileName: "denied.json", Attributes: map[string]string{"priority": "100"}, Metadata: map[string]any{"disable_cooling": true, "request_retry": 2}},
			} {
				registerPolicyAuth(t, manager, a)
			}
			ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
			req := cliproxyexecutor.Request{Model: "key-policy-model"}
			var err error
			switch kind {
			case "execute":
				_, err = manager.Execute(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
			case "count":
				_, err = manager.ExecuteCount(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
			case "stream":
				_, err = manager.ExecuteStream(ctx, []string{"claude"}, req, cliproxyexecutor.Options{Stream: true})
			}
			if err == nil {
				t.Fatal("expected terminal error")
			}
			counts := countRetryRoundIDs(executor.ids(kind))
			if counts["retry-policy-denied"] != 0 || counts["retry-policy-a"] != 3 || counts["retry-policy-b"] != 3 {
				t.Fatalf("retry counts = %v; calls=%v", counts, executor.ids(kind))
			}
		})
	}
}

func TestAPIKeyPolicyCreditsFallbackCannotEscape(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(policyTestConfig("allowed.json"))
	manager.RegisterExecutor(schedulerTestExecutor{provider: "antigravity"})
	registerPolicyAuth(t, manager, &Auth{ID: "credits-policy-denied", Provider: "antigravity", FileName: "denied.json"})
	candidates, err := manager.findAllAntigravityCreditsCandidateAuths(WithClientAPIKey(context.Background(), policyTestClientKey), "claude-model", cliproxyexecutor.Options{})
	if err != nil || len(candidates) != 0 {
		t.Fatalf("credits candidates = %v, %v", candidates, err)
	}
}

type policyHomeDispatcher struct{ email string }

func (policyHomeDispatcher) HeartbeatOK() bool       { return true }
func (policyHomeDispatcher) AbortAmbiguousDispatch() {}
func (d policyHomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	return json.Marshal(homeAuthDispatchResponse{Auth: Auth{ID: "policy-home-auth", Provider: "home-execution", Metadata: map[string]any{"email": d.email}}})
}

func TestAPIKeyPolicyHomeAndRetainedWebsocket(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	cfg := policyTestConfig("verified@example.com")
	cfg.Home.Enabled = true
	manager.SetConfig(cfg)
	manager.RegisterExecutor(&homeExecutionExecutor{})
	manager.PublishHomeDispatch(policyHomeDispatcher{email: "denied@example.com"}, executionregistry.New(), 1)
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	selected, err := manager.pickHomeDispatchSelection(ctx, "key-policy-model", cliproxyexecutor.Options{})
	if selected != nil {
		t.Fatal("denied Home auth selected")
	}
	requirePolicyDenied(t, err)
	manager.PublishHomeDispatch(policyHomeDispatcher{email: "verified@example.com"}, executionregistry.New(), 2)
	ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: "policy-home-session"}}
	selected, err = manager.pickHomeDispatchSelection(ctx, "key-policy-model", opts)
	if err != nil {
		t.Fatal(err)
	}
	selected.Retain()
	if !manager.retainHomeWebsocketSelection(ctx, opts, "key-policy-model", selected) {
		t.Fatal("failed to retain websocket selection")
	}
	cfg.APIKeyPolicies[0].AllowedAuths = nil
	manager.SetConfig(cfg)
	reused, err := manager.pickHomeDispatchSelection(ctx, "key-policy-model", opts)
	if reused != nil {
		t.Fatal("revoked websocket selection reused")
	}
	requirePolicyDenied(t, err)
	if selected.Active() {
		t.Fatal("denied retained selection was not released")
	}
}

type policyChangingRefreshExecutor struct{ unauthorizedRefreshExecutor }

func (e *policyChangingRefreshExecutor) Refresh(ctx context.Context, a *Auth) (*Auth, error) {
	updated, err := e.unauthorizedRefreshExecutor.Refresh(ctx, a)
	if updated != nil {
		updated.Metadata["email"] = "denied@example.com"
	}
	return updated, err
}

func TestAPIKeyPolicyRefreshRetryRevalidatesIdentity(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(policyTestConfig("verified@example.com"))
			executor := &policyChangingRefreshExecutor{unauthorizedRefreshExecutor: unauthorizedRefreshExecutor{id: "claude", tokenInvalid: map[string]struct{}{"expired-synthetic": {}}}}
			manager.RegisterExecutor(executor)
			registerPolicyAuth(t, manager, &Auth{ID: "refresh-policy-allowed", Provider: "claude", Metadata: map[string]any{"email": "verified@example.com", "access_token": "expired-synthetic", "refresh_token": "synthetic-refresh"}})
			ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
			req := cliproxyexecutor.Request{Model: "key-policy-model"}
			var err error
			if stream {
				_, err = manager.ExecuteStream(ctx, []string{"claude"}, req, cliproxyexecutor.Options{Stream: true})
			} else {
				_, err = manager.Execute(ctx, []string{"claude"}, req, cliproxyexecutor.Options{})
			}
			requirePolicyDenied(t, err)
			calls := executor.ExecuteCalls()
			if stream {
				calls = executor.StreamCalls()
			}
			if len(calls) != 1 || executor.RefreshCalls() != 1 {
				t.Fatalf("refresh crossed policy: calls=%v refreshes=%d", calls, executor.RefreshCalls())
			}
		})
	}
}

func TestAPIKeyPolicyDirectHTTPAndPreparation(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(policyTestConfig("allowed.json"))
	manager.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
	denied := &Auth{ID: "direct-policy-denied", Provider: "claude", FileName: "denied.json"}
	registerPolicyAuth(t, manager, denied)
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.invalid", nil)
	requirePolicyDenied(t, manager.InjectCredentials(req, denied.ID))
	requirePolicyDenied(t, manager.PrepareHttpRequest(ctx, denied, req))
	_, err := manager.HttpRequest(ctx, denied, req)
	requirePolicyDenied(t, err)
	_, err = manager.prepareRequestAuth(ctx, schedulerTestExecutor{provider: "claude"}, denied)
	requirePolicyDenied(t, err)
}
