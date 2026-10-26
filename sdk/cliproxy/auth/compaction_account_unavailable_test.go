package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Trust boundary: a signed conversation may never be replayed on another seat.
func TestCompactionAccountUnavailable(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		for _, kind := range []string{"signed", "protected", "ordinary"} {
			for _, dead := range []string{"unavailable", "unauthorized", "invalid_grant"} {
				t.Run(path+"/"+kind+"/"+dead, func(t *testing.T) {
					selector := NewSessionAffinitySelector(&FillFirstSelector{})
					defer selector.Stop()
					executor := &compactionAffinityExecutor{provider: "codex", firstID: t.Name() + "-A"}
					manager := newCompactionAffinityManager(t, selector, executor, "compact-dead-model", t.Name()+"-B")
					req, opts := compactionAffinityRequest("compact-dead-model", "Session-Id", false, true)
					if err := runCompactionAffinityRequest(t, manager, executor, path, req, opts); err != nil {
						t.Fatal(err)
					}
					if len(executor.attempts) != 1 || executor.attempts[0].authID != executor.firstID {
						t.Fatalf("initial selection = %v", executor.attempts)
					}
					if kind != "ordinary" {
						opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
						opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = "compact-dead-model"
						if err := selector.RecordCompactionOutput(executor.firstID, opts, []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`)); err != nil {
							t.Fatal(err)
						}
					}
					a, _ := manager.GetByID(executor.firstID)
					a.Unavailable = true
					a.ModelStates = map[string]*ModelState{"compact-dead-model": {Unavailable: true, Status: StatusError}}
					if dead != "unavailable" {
						a.Status = StatusError
						a.LastError = &Error{Code: "unauthorized", HTTPStatus: 401, Message: "private refresh detail"}
						if dead == "invalid_grant" {
							a.LastError = &Error{HTTPStatus: 400, Message: "invalid_grant: private refresh detail"}
						}
					}
					if _, err := manager.Update(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					executor.attempts = nil
					req, opts = compactionAffinityRequest("compact-dead-model", "Session-Id", kind == "signed", true)
					err := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
					if kind == "ordinary" {
						if err != nil || len(executor.attempts) != 1 || executor.attempts[0].authID != t.Name()+"-B" {
							t.Fatalf("ordinary session must reselect B: err=%v calls=%v", err, executor.attempts)
						}
						return
					}
					var typed *Error
					if !errors.As(err, &typed) || typed.Code != "compaction_account_unavailable" || typed.HTTPStatus != http.StatusServiceUnavailable || typed.Retryable {
						t.Fatalf("error = %v, want nonretryable typed 503", err)
					}
					digest := sha256.Sum256([]byte(executor.firstID))
					if !strings.Contains(typed.Message, fmt.Sprintf("sha256:%x", digest[:12])) || strings.Contains(typed.Message, executor.firstID) || strings.Contains(typed.Message, "private") {
						t.Fatalf("unsafe/missing account label: %s", typed.Message)
					}
					if len(executor.attempts) != 0 {
						t.Fatalf("dead hard pin reached upstream (B must have zero calls): %v", executor.attempts)
					}
				})
			}
		}
	}
}

func TestSelectorCompactionAccountUnavailable(t *testing.T) {
	for _, kind := range []string{"signed", "protected"} {
		for _, state := range []string{"dead", "cooldown", "disabled"} {
			t.Run(kind+"/"+state, func(t *testing.T) {
				selector := NewSessionAffinitySelector(&FillFirstSelector{})
				defer selector.Stop()
				a, b := &Auth{ID: "selector-seat-A"}, &Auth{ID: "selector-seat-B"}
				initial := affinityConversationOptions(false)
				if _, err := selector.Pick(context.Background(), "codex", "model", initial, []*Auth{a, b}); err != nil {
					t.Fatal(err)
				}
				recordAffinityTestOutput(t, selector, a.ID, initial)
				a.Unavailable = true
				if state == "disabled" {
					a.Disabled = true
				}
				if state == "cooldown" {
					a.Quota.Exceeded = true
					a.NextRetryAfter = time.Now().Add(time.Hour)
				}
				picked, err := selector.Pick(context.Background(), "codex", "model", affinityConversationOptions(kind == "signed"), []*Auth{a, b})
				if picked != nil || err == nil {
					t.Fatalf("hard pin selected %v, %v", picked, err)
				}
				if state == "cooldown" {
					var cooldown *modelCooldownError
					if !errors.As(err, &cooldown) {
						t.Fatal(err)
					}
					return
				}
				var typed *Error
				want := "compaction_account_unavailable"
				if state == "disabled" {
					want = "auth_unavailable"
				}
				if !errors.As(err, &typed) || typed.Code != want {
					t.Fatalf("selector error=%v want %s", err, want)
				}
			})
		}
	}
}

func TestExplicitPinAvailabilityErrors(t *testing.T) {
	for _, selectorKind := range []string{"fast", "legacy"} {
		for _, mixed := range []bool{false, true} {
			for _, state := range []string{"dead", "terminal", "missing", "disabled", "status-disabled", "cooldown", "recovered", "model-unsupported", "zero-weight"} {
				t.Run(fmt.Sprintf("%s/mixed-%t/%s", selectorKind, mixed, state), func(t *testing.T) {
					executor := &compactionAffinityExecutor{provider: "codex", firstID: t.Name() + "-A"}
					m := newCompactionAffinityManager(t, nil, executor, "pin-dead-model", t.Name()+"-B")
					m.SetSelector(&FillFirstSelector{})
					if selectorKind == "legacy" {
						m.SetSelector(&compactionAffinityFallback{preferredID: t.Name() + "-B"})
					}
					a, _ := m.GetByID(executor.firstID)
					pin := a.ID
					switch state {
					case "dead":
						a.Unavailable = true
					case "terminal":
						a.Unavailable = true
						a.Status = StatusError
						a.LastError = &Error{Code: "unauthorized", HTTPStatus: 401}
					case "missing":
						pin = "missing"
					case "disabled":
						a.Disabled = true
						a.Unavailable = true
					case "status-disabled":
						a.Status = StatusDisabled
						a.Unavailable = true
					case "cooldown":
						a.Unavailable = true
						a.Quota.Exceeded = true
						a.NextRetryAfter = time.Now().Add(time.Hour)
					case "recovered":
						a.Unavailable = true
						a.NextRetryAfter = time.Now().Add(-time.Hour)
					case "model-unsupported":
						a.Unavailable = true
					case "zero-weight":
						a.Unavailable = true
						a.Attributes = map[string]string{"weight": "0"}
						m.SetSelector(&WeightedRoundRobinSelector{})
					}
					if _, err := m.Update(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					opts := cliproxyexecutor.Options{Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: pin}}
					model := "pin-dead-model"
					if state == "model-unsupported" {
						model = "not-supported"
					}
					var err error
					var picked *Auth
					if mixed {
						picked, _, _, err = m.pickNextMixed(context.Background(), []string{"codex", "claude"}, model, opts, nil)
					} else {
						picked, _, err = m.pickNext(context.Background(), "codex", model, opts, nil)
					}
					if state == "recovered" {
						if err != nil || picked == nil || picked.ID != a.ID {
							t.Fatalf("recovered pin = %v, %v", picked, err)
						}
						return
					}
					if state == "cooldown" {
						var cooldown *modelCooldownError
						if !errors.As(err, &cooldown) {
							t.Fatalf("expected unchanged model cooldown: %v", err)
						}
						return
					}
					var typed *Error
					if !errors.As(err, &typed) {
						t.Fatalf("missing typed error: %v", err)
					}
					want := "auth_not_found"
					if state == "dead" || state == "terminal" {
						want = "compaction_account_unavailable"
					}
					if state == "status-disabled" && selectorKind == "legacy" {
						want = "auth_unavailable"
					}
					if typed.Code != want {
						t.Fatalf("code=%s want %s (error=%v)", typed.Code, want, err)
					}
					if want == "auth_not_found" && typed.Message != "no auth available" && typed.Message != "no auth candidates" {
						t.Fatalf("existing error changed: %+v", typed)
					}
				})
			}
		}
	}
}
