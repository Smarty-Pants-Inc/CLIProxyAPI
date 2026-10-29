package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const conductorSessionAffinityCooldownModel = "claude-3-7-sonnet"

func TestManagerClaudeSessionAffinityFallsBackFromQuotaCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, stream := range []bool{false, true} {
		name := "execute"
		if stream {
			name = "execute-stream"
		}
		t.Run(name, func(t *testing.T) {
			manager, _, calls := newConductorSessionAffinityCooldownManager(t)
			authA := t.Name() + "-auth-a"
			registerConductorSessionAffinityCooldownAuth(t, manager, authA, conductorSessionAffinityCooldownModel, 0, false)
			session := t.Name() + "-ordinary-session"

			if got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream); errRun != nil || got != authA {
				t.Fatalf("initial session request = (%q, %v), want auth %q", got, errRun, authA)
			}
			assertConductorSessionAffinityCooldownBinding(t, manager, session, authA)

			authB := t.Name() + "-auth-b"
			authC := t.Name() + "-auth-c"
			registerConductorSessionAffinityCooldownAuth(t, manager, authB, conductorSessionAffinityCooldownModel, 0, false)
			registerConductorSessionAffinityCooldownAuth(t, manager, authC, conductorSessionAffinityCooldownModel, 0, false)
			markConductorSessionAffinityCooldown(t, manager, authA, conductorSessionAffinityCooldownModel, http.StatusTooManyRequests)

			before := len(*calls)
			rebound, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream)
			if errRun != nil {
				t.Fatalf("request with bound auth cooling down: %v", errRun)
			}
			if rebound == authA || (rebound != authB && rebound != authC) {
				t.Fatalf("cooldown fallback auth = %q, want one healthy seat other than %q", rebound, authA)
			}
			if got := len(*calls) - before; got != 1 || (*calls)[before] != rebound {
				t.Fatalf("cooldown fallback upstream calls = %v, want exactly [%s]", (*calls)[before:], rebound)
			}
			assertConductorSessionAffinityCooldownBinding(t, manager, session, rebound)

			expireSessionAffinityPriorityModelCooldown(t, manager, authA, conductorSessionAffinityCooldownModel)
			before = len(*calls)
			got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream)
			if errRun != nil || got != rebound {
				t.Fatalf("same session after auth recovery = (%q, %v), want rebound seat %q", got, errRun, rebound)
			}
			if count := len(*calls) - before; count != 1 || (*calls)[before] != rebound {
				t.Fatalf("recovered-session upstream calls = %v, want exactly [%s]", (*calls)[before:], rebound)
			}
			assertConductorSessionAffinityCooldownBinding(t, manager, session, rebound)
		})
	}
}

func TestManagerClaudeSessionAffinityKeepsHealthyBoundSeat(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "execute"
		if stream {
			name = "execute-stream"
		}
		t.Run(name, func(t *testing.T) {
			manager, _, calls := newConductorSessionAffinityCooldownManager(t)
			authA := t.Name() + "-auth-a"
			session := t.Name() + "-ordinary-session"
			registerConductorSessionAffinityCooldownAuth(t, manager, authA, conductorSessionAffinityCooldownModel, 0, false)
			if got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream); errRun != nil || got != authA {
				t.Fatalf("initial session request = (%q, %v), want auth %q", got, errRun, authA)
			}

			higherPriority := t.Name() + "-higher-priority-auth"
			registerConductorSessionAffinityCooldownAuth(t, manager, higherPriority, conductorSessionAffinityCooldownModel, 10, false)
			before := len(*calls)
			got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream)
			if errRun != nil || got != authA {
				t.Fatalf("healthy bound session request = (%q, %v), want existing seat %q", got, errRun, authA)
			}
			if count := len(*calls) - before; count != 1 || (*calls)[before] != authA {
				t.Fatalf("healthy-bound upstream calls = %v, want exactly [%s]", (*calls)[before:], authA)
			}
			assertConductorSessionAffinityCooldownBinding(t, manager, session, authA)
		})
	}
}

func TestManagerClaudeSessionAffinityAllSeatsCoolingMakesNoUpstreamCalls(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, stream := range []bool{false, true} {
		name := "execute"
		if stream {
			name = "execute-stream"
		}
		t.Run(name, func(t *testing.T) {
			manager, _, calls := newConductorSessionAffinityCooldownManager(t)
			authA := t.Name() + "-auth-a"
			authB := t.Name() + "-auth-b"
			session := t.Name() + "-ordinary-session"
			registerConductorSessionAffinityCooldownAuth(t, manager, authA, conductorSessionAffinityCooldownModel, 0, false)
			if _, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream); errRun != nil {
				t.Fatalf("initial session request: %v", errRun)
			}
			registerConductorSessionAffinityCooldownAuth(t, manager, authB, conductorSessionAffinityCooldownModel, 0, false)
			markConductorSessionAffinityCooldown(t, manager, authA, conductorSessionAffinityCooldownModel, http.StatusTooManyRequests)
			markConductorSessionAffinityCooldown(t, manager, authB, conductorSessionAffinityCooldownModel, http.StatusTooManyRequests)

			before := len(*calls)
			_, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, stream)
			var cooldown *modelCooldownError
			if !errors.As(errRun, &cooldown) || statusCodeFromError(errRun) != http.StatusTooManyRequests {
				t.Fatalf("all-cooling request error = %v, want model cooldown 429", errRun)
			}
			if len(*calls) != before {
				t.Fatalf("all-cooling upstream calls = %v, want none", (*calls)[before:])
			}
		})
	}
}

func TestManagerClaudeSessionAffinityInvalidBoundSeatFallsBackToEligibleSeat(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, invalidation := range []string{"unavailable", "disabled", "missing", "model-ineligible"} {
		t.Run(invalidation, func(t *testing.T) {
			manager, _, calls := newConductorSessionAffinityCooldownManager(t)
			ctx := context.Background()
			authA := t.Name() + "-auth-a"
			authB := t.Name() + "-auth-b"
			decoy := t.Name() + "-disabled-decoy"
			session := t.Name() + "-ordinary-session"
			registerConductorSessionAffinityCooldownAuth(t, manager, authA, conductorSessionAffinityCooldownModel, 0, false)
			if got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, false); errRun != nil || got != authA {
				t.Fatalf("initial session request = (%q, %v), want auth %q", got, errRun, authA)
			}
			registerConductorSessionAffinityCooldownAuth(t, manager, authB, conductorSessionAffinityCooldownModel, 0, false)
			registerConductorSessionAffinityCooldownAuth(t, manager, decoy, conductorSessionAffinityCooldownModel, 0, true)

			switch invalidation {
			case "unavailable":
				markConductorSessionAffinityCooldown(t, manager, authA, conductorSessionAffinityCooldownModel, http.StatusServiceUnavailable)
			case "disabled":
				current, ok := manager.GetByID(authA)
				if !ok || current == nil {
					t.Fatalf("GetByID(%q) failed", authA)
				}
				current.Disabled = true
				current.Status = StatusDisabled
				if _, errUpdate := manager.Update(ctx, current); errUpdate != nil {
					t.Fatalf("disable bound auth: %v", errUpdate)
				}
			case "missing":
				manager.Remove(ctx, authA)
			case "model-ineligible":
				registry.GetGlobalRegistry().RegisterClient(authA, "claude", []*registry.ModelInfo{{ID: conductorSessionAffinityCooldownModel + "-other"}})
			}

			before := len(*calls)
			got, errRun := runConductorSessionAffinityCooldownRequest(t, manager, session, false)
			if errRun != nil || got != authB {
				t.Fatalf("fallback from %s bound seat = (%q, %v), want eligible seat %q", invalidation, got, errRun, authB)
			}
			if count := len(*calls) - before; count != 1 || (*calls)[before] != authB {
				t.Fatalf("invalid-bound upstream calls = %v, want exactly [%s] and never disabled decoy %s", (*calls)[before:], authB, decoy)
			}
			assertConductorSessionAffinityCooldownBinding(t, manager, session, authB)
		})
	}
}

func newConductorSessionAffinityCooldownManager(t *testing.T) (*Manager, *SessionAffinitySelector, *[]string) {
	t.Helper()
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RoundRobinSelector{}, TTL: time.Hour})
	t.Cleanup(affinity.Stop)
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	calls := []string{}
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "claude",
		mockCustomErrorExecutor: mockCustomErrorExecutor{
			identifier: "claude",
			executeFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
				calls = append(calls, auth.ID)
				return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
			},
		},
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			calls = append(calls, auth.ID)
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(fmt.Sprintf(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":%q}}`, auth.ID))}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	return manager, affinity, &calls
}

func registerConductorSessionAffinityCooldownAuth(t *testing.T, manager *Manager, id, model string, priority int, disabled bool) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(id) })
	auth := &Auth{
		ID:         id,
		Provider:   "claude",
		Status:     StatusActive,
		Attributes: map[string]string{"priority": fmt.Sprint(priority)},
	}
	if disabled {
		auth.Disabled = true
		auth.Status = StatusDisabled
	}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register(%s): %v", id, errRegister)
	}
}

func markConductorSessionAffinityCooldown(t *testing.T, manager *Manager, authID, model string, status int) {
	t.Helper()
	retryAfter := time.Hour
	manager.MarkResult(context.Background(), Result{
		AuthID: authID, Provider: "claude", Model: model, RetryAfter: &retryAfter,
		Error: &Error{HTTPStatus: status, Message: "seat unavailable"},
	})
}

func runConductorSessionAffinityCooldownRequest(t *testing.T, manager *Manager, session string, stream bool) (string, error) {
	t.Helper()
	req, opts := nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", false)
	opts.Headers = http.Header{"X-Session-Id": []string{session}}
	if !stream {
		response, errExecute := manager.Execute(context.Background(), []string{"claude"}, req, opts)
		return string(response.Payload), errExecute
	}
	result, errStream := manager.ExecuteStream(context.Background(), []string{"claude"}, req, opts)
	if errStream != nil {
		return "", errStream
	}
	if result == nil || result.Chunks == nil {
		return "", fmt.Errorf("ExecuteStream returned no chunks")
	}
	var payload []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			return string(payload), chunk.Err
		}
		payload = append(payload, chunk.Payload...)
	}
	event := bytes.TrimSpace(bytes.TrimPrefix(payload, []byte("data: ")))
	return gjson.GetBytes(event, "content_block.text").String(), nil
}

func assertConductorSessionAffinityCooldownBinding(t *testing.T, manager *Manager, session, wantAuth string) {
	t.Helper()
	auth, status := manager.LookupSessionAffinity("claude", conductorSessionAffinityCooldownModel, session)
	if status != "bound" || auth == nil || auth.ID != wantAuth {
		t.Fatalf("session binding = (%v, %q), want auth %q bound", auth, status, wantAuth)
	}
}
