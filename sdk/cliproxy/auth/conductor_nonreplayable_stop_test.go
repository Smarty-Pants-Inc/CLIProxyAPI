package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// These local wrappers mirror the executor contract without importing helps,
// which depends on auth and would introduce an import cycle.
type nonReplayableTestScopedError struct{ error }

func (e nonReplayableTestScopedError) Unwrap() error         { return e.error }
func (e nonReplayableTestScopedError) IsRequestScoped() bool { return true }

type nonReplayableTestStopError struct{ nonReplayableTestScopedError }

func (e nonReplayableTestStopError) IsRequestStop() bool { return true }

type nonReplayableTestStreamStopError struct{ error }

func (e nonReplayableTestStreamStopError) Unwrap() error       { return e.error }
func (e nonReplayableTestStreamStopError) IsRequestStop() bool { return true }

type nonReplayableTestQuotaError struct{ customStatusError }

func (e nonReplayableTestQuotaError) IsRequestScoped() bool { return false }

func TestNonReplayableZeroPayloadStreamStop(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	for _, action := range []string{"", RequestScopedActionContinue, RequestScopedActionContinueAndCooldown} {
		for _, pooled := range []bool{false, true} {
			for _, synchronous := range []bool{false, true} {
				for _, stop := range []bool{true, false} {
					if !stop && (action != "" || pooled) {
						continue
					}
					t.Run(fmt.Sprintf("action=%s/pooled=%t/sync=%t/stop=%t", action, pooled, synchronous, stop), func(t *testing.T) {
						const alias = "zero-payload-public-model"
						models := []internalconfig.OpenAICompatibilityModel{{Name: "first-upstream", Alias: alias}}
						if pooled {
							models = append(models, internalconfig.OpenAICompatibilityModel{Name: "second-upstream", Alias: alias})
						}
						m := NewManager(nil, nil, nil)
						m.SetConfig(&internalconfig.Config{OpenAICompatibility: []internalconfig.OpenAICompatibility{{
							Name: "pool", Models: models,
							RequestScopedErrors: []internalconfig.RequestScopedErrorRule{{Status: 429, Match: []string{"unsafe_quota"}, Action: action}},
						}}})
						m.SetRetryConfig(3, 0, 5)
						ids := []string{"zero-first-" + t.Name(), "zero-second-" + t.Name()}
						reg := registry.GetGlobalRegistry()
						for i, id := range ids {
							reg.RegisterClient(id, openAICompatPoolProviderKey, []*registry.ModelInfo{{ID: alias}})
							t.Cleanup(func() { reg.UnregisterClient(id) })
							_, errRegister := m.Register(context.Background(), &Auth{ID: id, Provider: openAICompatPoolProviderKey, Status: StatusActive,
								Attributes: map[string]string{"api_key": "test-key", "compat_name": "pool", "provider_key": openAICompatPoolProviderKey, "priority": fmt.Sprint(10 - i)}})
							if errRegister != nil {
								t.Fatal(errRegister)
							}
						}
						retryAfter := 17 * time.Second
						quota := nonReplayableTestQuotaError{customStatusError{code: 429, msg: "unsafe_quota", retryAfter: &retryAfter}}
						var failure error = quota
						if stop {
							failure = fmt.Errorf("executor: %w", nonReplayableTestStreamStopError{quota})
						}
						var calls []string
						m.RegisterExecutor(&customStreamMockExecutor{identifier: openAICompatPoolProviderKey,
							streamFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
								calls = append(calls, auth.ID+"|"+req.Model)
								cliproxyexecutor.MarkUpstreamAttempt(ctx)
								if auth.ID == ids[0] {
									if synchronous {
										return nil, failure
									}
									return streamErrorResult(http.Header{"X-Upstream": []string{"first"}}, failure), nil
								}
								ch := make(chan cliproxyexecutor.StreamChunk, 1)
								ch <- cliproxyexecutor.StreamChunk{Payload: []byte(`{"ok":true}`)}
								close(ch)
								return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
							}})
						started := time.Now()
						result, errStream := m.ExecuteStream(context.Background(), []string{openAICompatPoolProviderKey}, cliproxyexecutor.Request{Model: alias}, cliproxyexecutor.Options{})
						if stop {
							if result != nil || !isRequestStopError(errStream) || statusCodeFromError(errStream) != 429 || isRequestInvalidError(errStream) {
								t.Errorf("result=%v error=%v: want stop-only quota 429", result, errStream)
							}
							if got := retryAfterFromError(errStream); got == nil || *got != retryAfter {
								t.Errorf("RetryAfter=%v, want %v", got, retryAfter)
							}
							if len(calls) != 1 || calls[0] != ids[0]+"|first-upstream" {
								t.Errorf("calls=%v: want first credential/model once only", calls)
							}
						} else {
							if errStream != nil || result == nil {
								t.Fatalf("ordinary quota must retry: result=%v err=%v", result, errStream)
							}
							var payload []byte
							for chunk := range result.Chunks {
								payload = append(payload, chunk.Payload...)
							}
							if string(payload) != `{"ok":true}` || len(calls) != 2 || calls[1] != ids[1]+"|first-upstream" {
								t.Errorf("ordinary quota calls=%v payload=%s", calls, payload)
							}
						}
						first, _ := m.GetByID(ids[0])
						stateModel := alias
						if pooled {
							stateModel = "first-upstream"
						}
						state := first.ModelStates[stateModel]
						if state == nil || !state.Unavailable || !state.Quota.Exceeded || state.LastError == nil || state.LastError.HTTPStatus != 429 || state.NextRetryAfter.Before(started.Add(retryAfter)) {
							t.Errorf("quota model cooldown not retained: %+v", state)
						}
						if len(first.ModelStates) != 1 {
							t.Errorf("unexpected model state attribution: %v", first.ModelStates)
						}
						second, _ := m.GetByID(ids[1])
						if second.Unavailable || !second.NextRetryAfter.IsZero() {
							t.Error("second credential unexpectedly cooled down")
						}
					})
				}
			}
		}
	}
}

func TestNonReplayableStreamUnauthorizedDoesNotRefresh(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		t.Run(fmt.Sprintf("sync=%t", synchronous), func(t *testing.T) {
			stop := nonReplayableTestStreamStopError{customStatusError{code: http.StatusUnauthorized, msg: "unsafe unauthorized"}}
			executor := &claudeCancellationTestExecutor{streamFn: func(ctx context.Context, _ *Auth) (*cliproxyexecutor.StreamResult, error) {
				cliproxyexecutor.MarkUpstreamAttempt(ctx)
				if synchronous {
					return nil, stop
				}
				return streamErrorResult(nil, stop), nil
			}}
			m, _, model := newClaudeCancellationTestManager(t, executor, nil)
			_, errStream := m.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			if !isRequestStopError(errStream) || statusCodeFromError(errStream) != http.StatusUnauthorized {
				t.Fatalf("ExecuteStream error=%v, want unauthorized stop", errStream)
			}
			if executor.refreshCalls.Load() != 0 || executor.streamCalls.Load() != 1 {
				t.Fatalf("refresh=%d stream=%d, want 0/1", executor.refreshCalls.Load(), executor.streamCalls.Load())
			}
		})
	}
}

func TestNonReplayablePreferredExecutionAttemptRetainsStop(t *testing.T) {
	stop := newStreamBootstrapError(markUpstreamExecutionAttempt(nonReplayableTestStreamStopError{errors.New("unsafe current attempt")}), nil)
	previous := markUpstreamExecutionAttempt(errors.New("previous attempt"))
	if got := preferredExecutionAttemptError(stop, previous); got != stop || !isRequestStopError(got) {
		t.Fatalf("preferred error=%v, want current stop", got)
	}
}

func TestNonReplayableStopMatcherCannotContinue(t *testing.T) {
	body := `{"error":{"message":"unsafe_replay"}}`
	base := wrappedResponseBodyError{
		status: http.StatusBadGateway,
		msg:    "upstream response cannot be replayed",
		body:   []byte(body),
	}
	scoped := nonReplayableTestScopedError{error: base}
	stop := nonReplayableTestStopError{nonReplayableTestScopedError: scoped}
	for _, action := range []string{RequestScopedActionContinue, RequestScopedActionContinueAndCooldown} {
		t.Run(action, func(t *testing.T) {
			auth := &Auth{Metadata: map[string]any{
				"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{
					Status: http.StatusBadGateway, Match: []string{"unsafe_replay"}, Action: action,
				}},
			}}
			for _, err := range []error{stop, fmt.Errorf("outer wrapper: %w", stop)} {
				if !isRequestStopError(err) || !isRequestInvalidError(err) {
					t.Fatal("fake error must expose both stop and request-scoped markers")
				}
				if got := statusCodeFromError(err); got != http.StatusBadGateway {
					t.Fatalf("underlying status = %d, want %d", got, http.StatusBadGateway)
				}
				if got := extractErrorBody(err); got != body {
					t.Fatalf("underlying body = %q, want %q", got, body)
				}
				if got, ok := matchRequestScopedErrorAction(auth, err, nil); got != "" || ok {
					t.Errorf("hard stop matched configured action = (%q, %v), want (\"\", false)", got, ok)
				}
			}
			// Ordinary request-scoped errors must remain configurable.
			if isRequestStopError(scoped) || !isRequestInvalidError(scoped) {
				t.Fatal("ordinary scoped counterexample must not have a stop marker")
			}
			if got, ok := matchRequestScopedErrorAction(auth, scoped, nil); got != action || !ok {
				t.Errorf("ordinary scoped error matched action = (%q, %v), want (%q, true)", got, ok, action)
			}
			if got, ok := matchRequestScopedErrorAction(auth, nil, nil); got != "" || ok {
				t.Errorf("nil error matched action = (%q, %v), want (\"\", false)", got, ok)
			}
		})
	}
}

func TestNonReplayableStopManagerDoesNotReplay(t *testing.T) {
	for _, action := range []string{RequestScopedActionContinue, RequestScopedActionContinueAndCooldown} {
		for _, pooled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/pooled=%t", action, pooled), func(t *testing.T) {
				const alias = "nonreplayable-public-model"
				models := []internalconfig.OpenAICompatibilityModel{{Name: "first-upstream", Alias: alias}}
				if pooled {
					models = append(models, internalconfig.OpenAICompatibilityModel{Name: "second-upstream", Alias: alias})
				}
				m := NewManager(nil, nil, nil)
				m.SetConfig(&internalconfig.Config{OpenAICompatibility: []internalconfig.OpenAICompatibility{{
					Name: "pool", Models: models,
					RequestScopedErrors: []internalconfig.RequestScopedErrorRule{{
						Status: http.StatusBadGateway, Match: []string{"unsafe_replay"}, Action: action,
					}},
				}}})
				m.SetRetryConfig(3, 0, 5)

				firstID := "nonreplayable-first-" + t.Name()
				secondID := "nonreplayable-second-" + t.Name()
				reg := registry.GetGlobalRegistry()
				for i, id := range []string{firstID, secondID} {
					auth := &Auth{
						ID: id, Provider: openAICompatPoolProviderKey, Status: StatusActive,
						Attributes: map[string]string{
							"api_key": "test-key", "compat_name": "pool", "provider_key": openAICompatPoolProviderKey,
							"priority": fmt.Sprint(10 - i),
						},
					}
					reg.RegisterClient(id, openAICompatPoolProviderKey, []*registry.ModelInfo{{ID: alias}})
					t.Cleanup(func() { reg.UnregisterClient(id) })
					if _, errRegister := m.Register(context.Background(), auth); errRegister != nil {
						t.Fatalf("register auth: %v", errRegister)
					}
				}

				stop := nonReplayableTestStopError{nonReplayableTestScopedError{wrappedResponseBodyError{
					status: http.StatusBadGateway, msg: "nonreplayable response",
					body: []byte(`{"error":{"message":"unsafe_replay"}}`),
				}}}
				var calls []string
				m.RegisterExecutor(&mockCustomErrorExecutor{
					identifier: openAICompatPoolProviderKey,
					executeFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
						calls = append(calls, auth.ID+"|"+req.Model)
						cliproxyexecutor.MarkUpstreamAttempt(ctx)
						if auth.ID == firstID {
							return cliproxyexecutor.Response{}, stop
						}
						return cliproxyexecutor.Response{Payload: []byte(`{"ok":true}`)}, nil
					},
				})

				_, errExecute := m.Execute(context.Background(), []string{openAICompatPoolProviderKey}, cliproxyexecutor.Request{Model: alias}, cliproxyexecutor.Options{})
				var returnedStop nonReplayableTestStopError
				if !errors.As(errExecute, &returnedStop) {
					t.Errorf("Execute() error = %v, want original stop-scoped error", errExecute)
				}
				if len(calls) != 1 || calls[0] != firstID+"|first-upstream" {
					t.Errorf("execution calls = %v, want first credential and first upstream only", calls)
				}
				for _, id := range []string{firstID, secondID} {
					updated, ok := m.GetByID(id)
					if !ok || updated == nil {
						t.Fatalf("missing auth %s", id)
					}
					if updated.Unavailable || !updated.NextRetryAfter.IsZero() {
						t.Errorf("auth %s cooled down after request-scoped stop", id)
					}
					for model, state := range updated.ModelStates {
						if state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero()) {
							t.Errorf("auth %s model %s cooled down after request-scoped stop", id, model)
						}
					}
				}
			})
		}
	}
}

// A failed Home release acknowledgement during teardown must not replace an upstream request
// stop with a new home_unavailable 503: the stop, its 429 status and its cause stay primary.
func TestNonReplayableStopSurvivesFailedHomeRelease(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream_bootstrap=%t", bootstrap), func(t *testing.T) {
			upstream := &Error{HTTPStatus: http.StatusTooManyRequests, Message: "fixture quota exhausted"}
			executor := &retryContractHomeExecutor{failure: nonReplayableTestStreamStopError{upstream}, streamBootstrap: bootstrap}
			dispatcher := &accountedHomeExecutionDispatcher{auths: []Auth{
				{ID: "home-retry-a", Provider: "home-retry-contract", Status: StatusActive},
				{ID: "home-retry-b", Provider: "home-retry-contract", Status: StatusActive},
			}}
			registry := executionregistry.New()
			unacknowledged := make(chan struct{})
			var releaseSeen atomic.Bool
			registry.SetReleaseSink(func(group executionregistry.ReleaseGroup, sequence int64) *executionregistry.ReleaseTicket {
				releaseSeen.Store(true)
				return executionregistry.NewReleaseTicket(group, sequence, unacknowledged)
			})
			manager := NewManager(nil, nil, nil)
			manager.SetConfig(&internalconfig.Config{
				Home:                  internalconfig.HomeConfig{Enabled: true},
				CredentialConcurrency: internalconfig.CredentialConcurrencyConfig{CPACancelBound: 10 * time.Millisecond},
			})
			manager.PublishHomeDispatch(dispatcher, registry, 1)
			manager.RegisterExecutor(executor)

			retryLimit := -1
			_, err := manager.executeStreamMixedOnce(context.Background(), []string{"home-retry-contract"}, cliproxyexecutor.Request{Model: "gpt"}, cliproxyexecutor.Options{Stream: true}, 1, &retryLimit, 0, 0)
			if !releaseSeen.Load() {
				t.Fatal("Home release was not attempted")
			}
			var homeErr *Error
			if errors.As(err, &homeErr) && homeErr.Code == "home_unavailable" {
				t.Fatalf("release failure replaced the upstream stop: %v", err)
			}
			var stop interface{ IsRequestStop() bool }
			if !errors.As(err, &stop) || !stop.IsRequestStop() {
				t.Fatalf("request-stop marker lost: %T %v", err, err)
			}
			if !errors.Is(err, upstream) || statusCodeFromError(err) != http.StatusTooManyRequests {
				t.Fatalf("original 429 cause lost: %T %v", err, err)
			}
			if calls := len(executor.calls); calls != 1 {
				t.Fatalf("upstream attempts = %d, want 1", calls)
			}
		})
	}
}
