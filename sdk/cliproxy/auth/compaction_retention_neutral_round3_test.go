package auth

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func round3NeutralSigner(t *testing.T, authID string) (*SessionAffinitySelector, []byte, []string) {
	t.Helper()
	origin := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		StatePath: filepath.Join(t.TempDir(), "affinity.state"),
		Fallback:  &compactionAffinityFallback{preferredID: authID},
	})
	t.Cleanup(origin.Stop)
	origin.Cache().Stop()
	if err := origin.RecordCompactionOutput(authID, core.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"neutral-round3-signed"}]}`)); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"type":"response.append","input":[{"type":"compaction","encrypted_content":"neutral-round3-signed"}]}`)
	keys := compactionAffinityKeys(core.Options{OriginalRequest: payload})
	if len(keys) != 1 {
		t.Fatalf("produced signer keys=%v", keys)
	}
	if signer, known := origin.Cache().Get(keys[0]); !known || signer != authID || !origin.Cache().IsProtected(keys[0]) {
		t.Fatal("fixture lacks live protected evidence from actual output recording")
	}
	return origin, payload, keys
}

func round3NeutralRequireStateStop(t *testing.T, err error) {
	t.Helper()
	var cause *Error
	if !errors.As(err, &cause) || cause.Code != "affinity_state_unavailable" || cause.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("retention refusal=%v, want local affinity state 503", err)
	}
	if !IsLocalCompactionAffinityStop(wrapRequestStopError(err)) {
		t.Fatalf("retention refusal not recognized as local: %v", err)
	}
}

func TestCompactionRetentionNeutralRound3HelperPostSaveRefusal(t *testing.T) {
	origin, _, keys := round3NeutralSigner(t, "A")
	// Change future renewal TTL only, after proving the produced binding live.
	// The synchronous snapshot save precedes the cache's final retention check;
	// a one-nanosecond renewal cannot survive it. No sleep or failure hook.
	origin.Cache().SetTTL(time.Nanosecond)
	err := refreshCompactionSignerBindings(context.Background(), origin, "A", keys)
	round3NeutralRequireStateStop(t, err)
	if origin.Cache().PersistenceError() != nil {
		t.Fatal("fixture hit I/O failure rather than post-save retention refusal")
	}
}

func TestCompactionRetentionNeutralRound3CapturedDuplexPostSaveRefusal(t *testing.T) {
	origin, payload, _ := round3NeutralSigner(t, "A")
	m := NewManager(nil, origin, nil)
	opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[]}`)}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	m.SetSelector(&FillFirstSelector{}) // Admission must still use the captured origin.
	origin.Cache().SetTTL(time.Nanosecond)
	err = validate("A", payload)
	round3NeutralRequireStateStop(t, err)
	if !IsLocalCompactionAffinityStop(err) || origin.Cache().PersistenceError() != nil {
		t.Fatalf("captured callback lost local stop or encountered I/O failure: %v", err)
	}
}

// Compositional receiver proof, not an actual-socket test: invoke the real
// captured callback and mirror streamCodexDuplex's error channel/wrapper using
// the existing receiverDuplexAffinityError fixture (scope/status/Unwrap).
// An initial response.created forces public ExecuteStream past bootstrap into
// the real Manager receiver, with a live downstream parent.
type round3NeutralDuplexExecutor struct {
	compactionAffinityExecutor
	origin   *SessionAffinitySelector
	payload  []byte
	upstream bool
	terminal error
}

func (e *round3NeutralDuplexExecutor) ExecuteStream(ctx context.Context, a *Auth, _ core.Request, opts core.Options) (*core.StreamResult, error) {
	if err := e.attempt(ctx, a, opts); err != nil {
		return nil, err
	}
	if e.upstream {
		e.terminal = customStatusError{code: 503, msg: "session affinity state upstream failure"}
	} else {
		validate, ok := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
		if !ok {
			return nil, errors.New("captured duplex validator missing")
		}
		e.origin.Cache().SetTTL(time.Nanosecond)
		cause := validate(a.ID, e.payload)
		if cause == nil {
			return nil, errors.New("post-save retention refusal unexpectedly admitted")
		}
		e.terminal = &receiverDuplexAffinityError{cause: cause}
	}
	chunks := make(chan core.StreamChunk, 2)
	chunks <- core.StreamChunk{Payload: []byte("data: {\"type\":\"response.created\"}\n\n")}
	chunks <- core.StreamChunk{Err: e.terminal}
	close(chunks)
	return &core.StreamResult{Chunks: chunks}, nil
}

func TestCompactionRetentionNeutralRound3PublicManagerReceiverCompositional(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	for _, upstream := range []bool{false, true} {
		name := "local-retention"
		if upstream {
			name = "ordinary-upstream-control"
		}
		t.Run(name, func(t *testing.T) {
			authID, model := t.Name()+"-A", "neutral-round3-model"
			origin, payload, _ := round3NeutralSigner(t, authID)
			hook := &recordingHook{}
			m := NewManager(nil, origin, hook)
			m.SetRetryConfig(0, 0, 0)
			e := &round3NeutralDuplexExecutor{
				compactionAffinityExecutor: compactionAffinityExecutor{provider: "codex", firstID: authID},
				origin:                     origin, payload: payload, upstream: upstream,
			}
			m.RegisterExecutor(e)
			if _, err := m.Register(WithSkipPersist(context.Background()), &Auth{
				ID: authID, Provider: "codex", Status: StatusActive,
				Metadata: map[string]any{"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{
					Status: 503, Match: []string{"session affinity state"}, Action: "stop-and-cooldown",
				}}},
			}); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(authID, "codex", []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, opts := compactionAffinityRequest(model, "none", false, false)
			stream, err := m.ExecuteStream(parent, []string{"codex"}, req, opts)
			if err != nil || stream == nil {
				t.Fatalf("public stream bootstrap=%v", err)
			}
			var received error
			var payloads int
			for chunk := range stream.Chunks {
				if len(chunk.Payload) > 0 {
					payloads++
				}
				if chunk.Err != nil {
					received = chunk.Err
				}
			}
			if parent.Err() != nil || received != e.terminal || payloads != 1 || len(e.attempts) != 1 {
				t.Fatalf("receiver path: parent=%v error=%v payloads=%d attempts=%d", parent.Err(), received, payloads, len(e.attempts))
			}
			current, _ := m.GetByID(authID)
			result := hook.lastResult.Load()
			if upstream {
				if IsLocalCompactionAffinityStop(received) || result == nil || result.Success || current.Failed != 1 || !current.Unavailable || current.NextRetryAfter.IsZero() {
					t.Fatalf("ordinary upstream failure escaped accounting/cooldown: result=%+v auth=%+v", result, current)
				}
			} else {
				round3NeutralRequireStateStop(t, received)
				if !IsLocalCompactionAffinityStop(received) || result != nil || current.Failed != 0 || current.Success != 0 || current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || len(current.ModelStates) != 0 {
					t.Fatalf("local retention refusal changed result/availability: result=%+v auth=%+v", result, current)
				}
				if origin.Cache().PersistenceError() != nil {
					t.Fatal("expected post-save retention failure, not I/O failure")
				}
			}
		})
	}
}

func TestCompactionRetentionNeutralRound3RenewalCancellationAndAccountUnavailableControls(t *testing.T) {
	origin, _, keys := round3NeutralSigner(t, "A")
	before := round3SignerExpiry(t, origin, keys[0])
	origin.Cache().SetTTL(12 * time.Hour)
	if err := refreshCompactionSignerBindings(context.Background(), origin, "A", keys); err != nil {
		t.Fatalf("normal renewal refused: %v", err)
	}
	after := round3SignerExpiry(t, origin, keys[0])
	if !after.After(before) {
		t.Fatal("normal renewal did not advance signer expiry")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := refreshCompactionSignerBindings(ctx, origin, "A", keys); !errors.Is(err, context.Canceled) {
		t.Fatalf("helper erased cancellation cause: %v", err)
	}
	m := NewManager(nil, origin, nil)
	opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[]}`)}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	opts.Metadata[compactionRequestContextMetadataKey] = ctx
	m.prepareCompactionDuplexValidation(opts)
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	if err := validate("A", []byte(`{"input":[{"type":"compaction","encrypted_content":"neutral-round3-signed"}]}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("captured callback erased cancellation cause: %v", err)
	}
	if !round3SignerExpiry(t, origin, keys[0]).Equal(after) {
		t.Fatal("canceled renewal changed signer expiry")
	}
	ordinary := wrapRequestStopError(compactedAuthUnavailableError())
	var unavailable *Error
	if IsLocalCompactionAffinityStop(ordinary) || !errors.As(ordinary, &unavailable) || unavailable.Code != "auth_unavailable" {
		t.Fatalf("ordinary account unavailable semantics changed: %v", ordinary)
	}
}
