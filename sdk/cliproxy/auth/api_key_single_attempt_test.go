package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Embed the existing executor for the unused refresh and raw HTTP methods.
type singleAttemptTestExecutor struct {
	retryRoundCallExecutor
	failure  error
	models   []string
	policies []bool
	singles  []bool
}

func (e *singleAttemptTestExecutor) record(ctx context.Context, a *Auth, req coreexecutor.Request, kind string) error {
	e.models = append(e.models, req.Model)
	e.policies = append(e.policies, coreexecutor.HasClientExecutionPolicy(ctx))
	e.singles = append(e.singles, coreexecutor.ClientSingleAttempt(ctx))
	switch kind {
	case "execute":
		e.executeIDs = append(e.executeIDs, a.ID)
	case "count":
		e.countIDs = append(e.countIDs, a.ID)
	case "stream":
		e.streamIDs = append(e.streamIDs, a.ID)
	}
	return e.failure
}
func (e *singleAttemptTestExecutor) Execute(ctx context.Context, a *Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, e.record(ctx, a, req, "execute")
}
func (e *singleAttemptTestExecutor) CountTokens(ctx context.Context, a *Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, e.record(ctx, a, req, "count")
}
func (e *singleAttemptTestExecutor) ExecuteStream(ctx context.Context, a *Auth, req coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, e.record(ctx, a, req, "stream")
}

func invokeSingleAttemptTest(m *Manager, ctx context.Context, kind string) error {
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

func TestAPIKeySingleAttemptManagerRotationAndRounds(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		for _, mode := range []string{"single", "policy-retries", "unpolicied"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				m := NewManager(nil, nil, nil)
				t.Cleanup(m.StopAutoRefresh)
				cfg := policyTestConfig("allowed-*.json")
				cfg.APIKeyPolicies[0].SingleAttempt = mode == "single"
				m.SetConfig(cfg)
				m.SetRetryConfig(2, 0, 0)
				failure := &Error{HTTPStatus: http.StatusInternalServerError, Message: "single-attempt synthetic failure"}
				exec := &singleAttemptTestExecutor{retryRoundCallExecutor: retryRoundCallExecutor{identifier: "claude"}, failure: failure}
				m.RegisterExecutor(exec)
				for _, id := range []string{"a", "b"} {
					registerPolicyAuth(t, m, &Auth{ID: "single-attempt-" + id, Provider: "claude", FileName: "allowed-" + id + ".json", Metadata: map[string]any{"request_retry": 2, "disable_cooling": true}})
				}
				key := policyTestClientKey
				if mode == "unpolicied" {
					key = "synthetic-unpolicied"
				}
				ctx := WithClientAPIKey(context.Background(), key)
				if got := m.SingleAttemptClient(ctx); got != (mode == "single") {
					t.Fatalf("SingleAttemptClient = %v", got)
				}
				err := invokeSingleAttemptTest(m, ctx, kind)
				if mode == "policy-retries" {
					requirePolicyDenied(t, err)
				} else if !errors.Is(err, failure) {
					t.Fatalf("error = %v, want original failure", err)
				}
				calls := exec.ids(kind)
				if mode == "single" {
					if len(calls) != 1 {
						t.Fatalf("calls = %v, want exactly one", calls)
					}
				} else {
					counts := countRetryRoundIDs(calls)
					if len(counts) != 2 || counts["single-attempt-a"] != 3 || counts["single-attempt-b"] != 3 {
						t.Fatalf("calls = %v, want both credentials in three rounds", calls)
					}
				}
				for i := range exec.models {
					if exec.policies[i] != (mode != "unpolicied") || exec.singles[i] != (mode == "single") {
						t.Fatalf("attempt %d policy=%v single=%v", i, exec.policies[i], exec.singles[i])
					}
				}
			})
		}
	}
}

func TestAPIKeySingleAttemptManager400OverridesContinue(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		for _, single := range []bool{false, true} {
			for _, action := range []string{RequestScopedActionContinue, RequestScopedActionContinueAndCooldown} {
				t.Run(kind+"/"+action+map[bool]string{false: "/retry-policy", true: "/single"}[single], func(t *testing.T) {
					m := NewManager(nil, nil, nil)
					t.Cleanup(m.StopAutoRefresh)
					cfg := policyTestConfig("allowed-*.json")
					cfg.APIKeyPolicies[0].SingleAttempt = single
					m.SetConfig(cfg)
					m.SetRetryConfig(2, 0, 0)
					failure := customStatusError{code: 400, msg: `{"error":{"code":"context_length_exceeded"}}`}
					exec := &singleAttemptTestExecutor{retryRoundCallExecutor: retryRoundCallExecutor{identifier: "claude"}, failure: failure}
					m.RegisterExecutor(exec)
					for _, id := range []string{"a", "b"} {
						a := &Auth{ID: "single-400-" + id, Provider: "claude", FileName: "allowed-" + id + ".json", Metadata: map[string]any{"request_retry": 2, "disable_cooling": true, "request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 400, Match: []string{"context_length_exceeded"}, Action: action}}}}
						if got, ok := matchRequestScopedErrorAction(a, failure, cfg); !ok || got != action {
							t.Fatalf("test rule did not match: %q %v", got, ok)
						}
						registerPolicyAuth(t, m, a)
					}
					ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
					if !m.ClientExecutionMustStop(ctx, failure) || m.ClientExecutionMustStop(ctx, nil) {
						t.Fatal("terminal helper must stop 400, not nil")
					}
					err := invokeSingleAttemptTest(m, ctx, kind)
					if statusCodeFromError(err) != 400 {
						t.Fatalf("error=%v, want 400", err)
					}
					if calls := exec.ids(kind); len(calls) != 1 {
						t.Fatalf("continue rule escaped terminal 400: %v", calls)
					}
				})
			}
		}
	}
}

func TestAPIKeySingleAttemptManagerKeepsOriginalModel(t *testing.T) {
	for _, kind := range []string{"execute", "count", "stream"} {
		t.Run(kind, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			t.Cleanup(m.StopAutoRefresh)
			cfg := policyTestConfig("allowed.json")
			cfg.APIKeyPolicies[0].SingleAttempt = true
			m.SetConfig(cfg)
			m.SetOAuthModelAlias(map[string][]internalconfig.OAuthModelAlias{"claude": {{Name: "different-upstream-model", Alias: "key-policy-model"}}})
			a := &Auth{ID: "single-model-guard", Provider: "claude", FileName: "allowed.json", Metadata: map[string]any{"type": "claude"}}
			registerPolicyAuth(t, m, a)
			if got := m.applyOAuthModelAlias(a, "key-policy-model"); got != "different-upstream-model" {
				t.Fatalf("alias fixture not active: %q", got)
			}
			exec := &singleAttemptTestExecutor{retryRoundCallExecutor: retryRoundCallExecutor{identifier: "claude"}, failure: &Error{HTTPStatus: 503, Message: "synthetic"}}
			m.RegisterExecutor(exec)
			_ = invokeSingleAttemptTest(m, WithClientAPIKey(context.Background(), policyTestClientKey), kind)
			if len(exec.models) != 1 {
				t.Fatalf("models=%v, want one original-model attempt", exec.models)
			}
			if exec.models[0] != "key-policy-model" {
				t.Fatalf("sent substituted model: %v", exec.models)
			}
		})
	}
}
