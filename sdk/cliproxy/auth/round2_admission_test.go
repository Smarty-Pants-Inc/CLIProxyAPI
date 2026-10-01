package auth

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type round2PrepareExecutor struct {
	requestPrepareExecutor
	prepare   func()
	httpCalls int
}

func (e *round2PrepareExecutor) PrepareRequest(req *http.Request, a *Auth) error {
	req.Header.Set("Authorization", "synthetic")
	return nil
}
func (e *round2PrepareExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	e.httpCalls++
	return &http.Response{StatusCode: 200}, nil
}
func (e *round2PrepareExecutor) PrepareRequestAuth(ctx context.Context, a *Auth) (*Auth, error) {
	if e.prepare != nil {
		e.prepare()
	}
	return e.requestPrepareExecutor.PrepareRequestAuth(ctx, a)
}

func TestRound2Finding9PreparedCredentialUnit(t *testing.T) {
	manager := NewManager(nil, nil, nil)
	base, err := manager.Register(context.Background(), &Auth{
		ID: "prepared-unit", Provider: "codex", FileName: "credential.json",
		Attributes: map[string]string{"email": "a@example.com"},
		Metadata:   map[string]any{"email": "a@example.com", "access_token": "synthetic-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated := base.Clone()
	rotated.Metadata["access_token"] = "synthetic-new-a"
	if _, err := manager.Update(context.Background(), rotated); err != nil {
		t.Fatal(err)
	}
	prepared := base.Clone()
	prepared.Metadata["access_token"] = "synthetic-late-a"
	prepared.Metadata["email"] = "stale-profile@example.com"
	prepared.Metadata["project_id"] = "discovered-project"
	current, err := manager.UpdatePreparedAuth(context.Background(), base, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if current.Metadata["access_token"] != "synthetic-new-a" || current.Metadata["email"] != "a@example.com" || current.Attributes["email"] != "a@example.com" || current.Metadata["project_id"] != "discovered-project" {
		t.Fatalf("preparation split the token/identity unit or lost discovery: %+v", current)
	}
}

func TestRound2Finding11HTTPAdmissionContext(t *testing.T) {
	for _, mode := range []string{"unbound", "same-principal", "conflicting-principal"} {
		t.Run(mode, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := policyTestConfig("allowed-*.json")
			cfg.APIKeyPolicies[0].AllowedModels = policyModels("key-policy-model")
			cap := int64(5)
			cfg.APIKeyPolicies[0].DailyTokenCap = &cap
			manager.SetConfig(cfg)
			executor := &round2PrepareExecutor{}
			manager.RegisterExecutor(executor)
			allowed := &Auth{ID: "http-admitted", Provider: "antigravity", FileName: "allowed-one.json"}
			denied := &Auth{ID: "http-denied", Provider: "antigravity", FileName: "denied.json"}
			registerPolicyAuth(t, manager, allowed)
			registerPolicyAuth(t, manager, denied)
			source := manager.WithClientRequest(WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies), "key-policy-model")
			req, _ := http.NewRequestWithContext(source, http.MethodGet, "http://example.invalid", nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "same-principal":
				floor := policyTestConfig("allowed-one.json")
				ctx = WithClientAPIKeyPolicies(ctx, policyTestClientKey, floor.APIKeyPolicies)
			case "conflicting-principal":
				ctx = WithClientAPIKey(ctx, "other-principal")
			}
			err := manager.PrepareHttpRequest(ctx, allowed, req)
			if mode == "conflicting-principal" {
				requirePolicyDenied(t, err)
				if req.Header.Get("Authorization") != "" {
					t.Fatal("injected credentials for conflicting principals")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			digest, _ := req.Context().Value(clientAPIKeyHashContextKey{}).(string)
			if digest != cfg.APIKeyPolicies[0].KeySHA256 {
				t.Error("HTTP preparation erased authenticated digest")
			}
			if got := ClientRequestedModelFromContext(req.Context()); got != "key-policy-model" {
				t.Error("HTTP preparation erased requested model")
			}
			manager.SetConfig(&internalconfig.Config{})
			requirePolicyDenied(t, manager.InjectCredentials(req, denied.ID))
			_, err = manager.HttpRequest(context.Background(), denied, req)
			requirePolicyDenied(t, err)
			requireControlStatus(t, manager.ValidateClientRequest(req.Context(), "denied-model"), 403)
			if mode == "same-principal" {
				requirePolicyDenied(t, manager.ValidateClientAuth(req.Context(), &Auth{FileName: "allowed-two.json"}))
			}
			usage := coreusage.NewManager(0)
			t.Cleanup(usage.Stop)
			usage.Publish(req.Context(), coreusage.Record{RequestID: "http-admission-usage", Detail: coreusage.Detail{InputTokens: 5}})
			requireControlStatus(t, manager.ValidateClientRequest(req.Context(), "key-policy-model"), 429)
			if executor.httpCalls != 0 {
				t.Fatal("denied HTTP request dispatched")
			}
			cancel()
			if req.Context().Err() != context.Canceled {
				t.Fatal("replacement cancellation parent not retained")
			}
		})
	}
}

func TestRound2Finding15PolicyUnavailableNeutral(t *testing.T) {
	for _, model := range []string{"", "key-policy-model"} {
		t.Run("model="+model, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			a := &Auth{ID: "neutral-shared", Provider: "antigravity", FileName: "allowed.json"}
			registerPolicyAuth(t, manager, a)
			before, _ := manager.GetByID(a.ID)
			rejected := apiKeyPolicyUnavailableError()
			if !rejected.IsRequestScoped() {
				t.Error("allowlist refusal is not request scoped")
			}
			for _, action := range []string{RequestScopedActionStopAndCooldown, RequestScopedActionContinueAndCooldown} {
				rules := a.Clone()
				rules.Metadata = map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 503, MatchRegexr: []string{".*"}, Action: action}}}
				if _, matched := matchRequestScopedErrorAction(rules, rejected, nil); matched {
					t.Error("cooldown override matched client-local admission error")
				}
				result := Result{Error: cloneError(rejected)}
				applyRequestScopedActionToResult(action, true, &result)
				if result.Error.Code != rejected.Code {
					t.Error("cooldown override reclassified client-local admission error")
				}
			}
			converted := resultErrorFromError(rejected)
			if !shouldSkipCredentialCooldown(converted) {
				t.Error("policy refusal would cool credential")
			}
			manager.MarkResult(context.Background(), Result{AuthID: a.ID, Provider: a.Provider, Model: model, Error: converted})
			after, _ := manager.GetByID(a.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("policy refusal mutated shared credential: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestRound2Finding15PreparationRevocationAcrossPaths(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		t.Run(path, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := policyTestConfig("allowed.json")
			manager.SetConfig(cfg)
			executor := &round2PrepareExecutor{prepare: func() { manager.SetConfig(policyTestConfig("revoked.json")) }}
			manager.RegisterExecutor(executor)
			a := &Auth{ID: "prep-revocation-" + path, Provider: "antigravity", FileName: "allowed.json", Metadata: map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 503, MatchRegexr: []string{".*"}, Action: RequestScopedActionContinueAndCooldown}}}}
			registerPolicyAuth(t, manager, a)
			ctx := WithClientAPIKeyPolicies(context.Background(), policyTestClientKey, cfg.APIKeyPolicies)
			req := coreexecutor.Request{Model: "key-policy-model"}
			var err error
			switch path {
			case "execute":
				_, err = manager.Execute(ctx, []string{"antigravity"}, req, coreexecutor.Options{})
			case "count":
				_, err = manager.ExecuteCount(ctx, []string{"antigravity"}, req, coreexecutor.Options{})
			case "stream":
				_, err = manager.ExecuteStream(ctx, []string{"antigravity"}, req, coreexecutor.Options{Stream: true})
			}
			requirePolicyDenied(t, err)
			if executor.executeCalls.Load() != 0 || executor.prepareCalls.Load() != 1 {
				t.Fatal("revoked request dispatched or prepared again")
			}
			current, _ := manager.GetByID(a.ID)
			if current.Unavailable || current.LastError != nil || !current.NextRetryAfter.IsZero() || len(current.ModelStates) != 0 || current.Failed != 0 {
				t.Fatalf("preparation refusal penalized shared credential: %+v", current)
			}
			executor.prepare = nil
			_, err = manager.Execute(context.Background(), []string{"antigravity"}, req, coreexecutor.Options{})
			if err != nil {
				t.Fatalf("unrestricted client cannot use shared credential: %v", err)
			}
		})
	}
}
