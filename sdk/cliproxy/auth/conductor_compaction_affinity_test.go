package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// This fallback deliberately prefers B after the first request. The real
// SessionAffinitySelector must override it, not merely select A by coincidence.
type compactionAffinityFallback struct {
	preferredID string
}

func (s *compactionAffinityFallback) Pick(_ context.Context, _, _ string, _ cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	for _, auth := range auths {
		if auth != nil && auth.ID == s.preferredID {
			return auth, nil
		}
	}
	return quotaAttemptIsolationSelector{}.Pick(context.Background(), "", "", cliproxyexecutor.Options{}, auths)
}

type compactionAffinityCall struct {
	authID string
	pinned string
}

type compactionAffinityExecutor struct {
	compactTestExecutor
	provider       string
	firstID        string
	failure        error
	bootstrapChunk bool
	output         []byte
	streamOutput   [][]byte
	onExecute      func()
	attempts       []compactionAffinityCall
}

func (e *compactionAffinityExecutor) Identifier() string { return e.provider }

func (e *compactionAffinityExecutor) attempt(ctx context.Context, auth *Auth, opts cliproxyexecutor.Options) error {
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	pinned, _ := opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey].(string)
	e.attempts = append(e.attempts, compactionAffinityCall{authID: auth.ID, pinned: pinned})
	if auth.ID == e.firstID {
		return e.failure
	}
	return nil
}

func (e *compactionAffinityExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if errAttempt := e.attempt(ctx, auth, opts); errAttempt != nil {
		return cliproxyexecutor.Response{}, errAttempt
	}
	if e.onExecute != nil {
		e.onExecute()
	}
	if e.output != nil {
		return cliproxyexecutor.Response{Payload: e.output}, nil
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"status":"ok"}`)}, nil
}

func (e *compactionAffinityExecutor) ExecuteStream(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	errAttempt := e.attempt(ctx, auth, opts)
	if errAttempt != nil && !e.bootstrapChunk {
		return nil, errAttempt
	}
	if errAttempt == nil && e.onExecute != nil {
		e.onExecute()
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, len(e.streamOutput)+1)
	if errAttempt != nil {
		// A real bootstrap failure: no payload has reached the downstream yet.
		chunks <- cliproxyexecutor.StreamChunk{Err: errAttempt}
	} else if len(e.streamOutput) > 0 {
		for _, payload := range e.streamOutput {
			chunks <- cliproxyexecutor.StreamChunk{Payload: payload}
		}
	} else {
		chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(`data: {"status":"ok"}` + "\n\n")}
	}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

// Drain streams through the public boundary: bootstrap errors may be returned
// either directly or as the sole error chunk in a StreamResult.
func runCompactionAffinityRequest(t *testing.T, manager *Manager, executor *compactionAffinityExecutor, path string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) error {
	t.Helper()
	if path == "execute" {
		resp, errExecute := manager.Execute(context.Background(), []string{executor.provider}, req, opts)
		if errExecute == nil && string(resp.Payload) != `{"status":"ok"}` && string(resp.Payload) != string(executor.output) {
			t.Fatalf("unexpected successful response: %s", resp.Payload)
		}
		return errExecute
	}
	opts.Stream = true
	stream, errStream := manager.ExecuteStream(context.Background(), []string{executor.provider}, req, opts)
	if errStream != nil {
		return errStream
	}
	if stream == nil || stream.Chunks == nil {
		t.Fatal("ExecuteStream returned no stream and no error")
	}
	var terminal error
	var receivedPayload bool
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			terminal = chunk.Err
		}
		receivedPayload = receivedPayload || len(chunk.Payload) > 0
	}
	if terminal != nil && receivedPayload {
		t.Fatal("bootstrap failure leaked a success payload")
	}
	if terminal == nil && !receivedPayload {
		t.Fatal("successful stream contained no payload")
	}
	return terminal
}

func newCompactionAffinityManager(t *testing.T, selector *SessionAffinitySelector, executor *compactionAffinityExecutor, model, secondID string) *Manager {
	t.Helper()
	manager := NewManager(nil, selector, nil)
	// Keep the tests deterministic and fast while leaving within-round failover
	// unlimited. The uncompacted counterexample proves B is actually eligible.
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	for _, id := range []string{executor.firstID, secondID} {
		if _, errRegister := manager.Register(context.Background(), &Auth{
			ID: id, Provider: executor.provider, Status: StatusActive,
		}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, executor.provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	return manager
}

func compactionAffinityRequest(model, identity string, compacted, keepIdentity bool) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	input := `[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]`
	if compacted {
		input = `[{"type":"compaction","encrypted_content":"signed-block"},{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]`
	}
	body := `{"input":` + input
	if identity == "prompt_cache_key" && keepIdentity {
		body += `,"prompt_cache_key":"stable-conversation"`
	}
	body += `}`
	opts := cliproxyexecutor.Options{
		SourceFormat:    sdktranslator.FormatOpenAIResponse,
		OriginalRequest: []byte(body),
		Metadata:        map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "compaction-affinity-caller"},
	}
	if identity == "Session-Id" && keepIdentity {
		opts.Headers = make(http.Header)
		opts.Headers.Set("Session-Id", "stable-conversation")
	}
	// This is ordinary Responses execution containing a compaction input item,
	// NOT the responses/compact endpoint (whose cooldown rules are different).
	return cliproxyexecutor.Request{Model: model, Payload: []byte(body)}, opts
}

func assertCompactionAffinityOnlyA(t *testing.T, executor *compactionAffinityExecutor, pinned bool) {
	t.Helper()
	for _, call := range executor.attempts {
		if call.authID != executor.firstID {
			t.Errorf("compacted request invoked %q, want only %q", call.authID, executor.firstID)
		}
		if pinned && call.pinned != executor.firstID {
			t.Errorf("executor pinned_auth_id = %q, want %q", call.pinned, executor.firstID)
		}
	}
}

func TestManagerCompactionAffinityFailsClosedAndSurvivesRestart(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		for _, identity := range []string{"prompt_cache_key", "Session-Id", "none"} {
			for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
				t.Run(fmt.Sprintf("%s/%s/%d", path, identity, status), func(t *testing.T) {
					model := "compaction-affinity-model"
					firstID := t.Name() + "-a"
					secondID := t.Name() + "-b"
					fallback := &compactionAffinityFallback{preferredID: firstID}
					statePath := filepath.Join(t.TempDir(), "affinity.json")
					selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
						Fallback: fallback, StatePath: statePath,
					})
					// Stop explicitly before restart, and also on early test failure.
					defer selector.Stop()
					if selector.cache.ttl != 6*time.Hour {
						t.Errorf("default affinity TTL = %v, want 6h", selector.cache.ttl)
					}
					upstreamErr := compactTestStatusError{code: status, msg: fmt.Sprintf("account A upstream %d", status)}
					executor := &compactionAffinityExecutor{
						provider: "codex", firstID: firstID, bootstrapChunk: path == "stream-bootstrap",
						output: []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`),
						streamOutput: [][]byte{
							[]byte(`data: {"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"signed-`),
							[]byte("block\"}}\n\n"),
						},
					}
					manager := newCompactionAffinityManager(t, selector, executor, model, secondID)
					initialReq, initialOpts := compactionAffinityRequest(model, identity, false, true)
					if errInitial := runCompactionAffinityRequest(t, manager, executor, path, initialReq, initialOpts); errInitial != nil {
						t.Fatalf("initial conversation failed: %v", errInitial)
					}
					if len(executor.attempts) != 1 || executor.attempts[0].authID != firstID {
						t.Fatalf("initial conversation did not establish A: %#v", executor.attempts)
					}
					// Restart BEFORE the very first replay: only production-time
					// signer evidence, not input seeding or LCP memory, can pin A.
					selector.Stop()
					selector = NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
						Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
					})
					defer selector.Stop()
					manager = newCompactionAffinityManager(t, selector, executor, model, secondID)
					executor.output = nil
					executor.streamOutput = nil
					executor.failure = upstreamErr
					executor.attempts = nil
					compactReq, compactOpts := compactionAffinityRequest(model, identity, true, false)
					errCompact := runCompactionAffinityRequest(t, manager, executor, path, compactReq, compactOpts)
					assertCompactionAffinityOnlyA(t, executor, true)
					if len(executor.attempts) != 1 {
						t.Errorf("forced upstream failure attempts = %#v, want one A attempt", executor.attempts)
					}
					var statusErr cliproxyexecutor.StatusError
					if !errors.As(errCompact, &statusErr) || statusErr.StatusCode() != status {
						t.Errorf("compacted error = %v, want original upstream status %d", errCompact, status)
					}

					// New options, no inherited pinned/canonical metadata, no explicit
					// identity: the protected block digest must survive OnResult failure.
					executor.attempts = nil
					replayReq, replayOpts := compactionAffinityRequest(model, identity, true, false)
					errReplay := runCompactionAffinityRequest(t, manager, executor, path, replayReq, replayOpts)
					assertCompactionAffinityOnlyA(t, executor, true)
					if errReplay == nil {
						t.Error("replay succeeded while its pinned account was still failing/cooling")
					}

					// Restart directly after failure, before any compacted success can
					// repair a binding that OnResult erroneously deleted.
					selector.Stop()
					state, errRead := os.ReadFile(statePath)
					if errRead != nil {
						t.Fatalf("read persisted affinity state: %v", errRead)
					}
					if strings.Contains(string(state), "signed-block") {
						t.Error("persisted affinity state leaked the encrypted block instead of a digest")
					}
					// A fresh selector AND manager cannot reuse in-memory bindings.
					// Its fallback prefers B, so persistence must be what retains A.
					restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
						Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
					})
					defer restarted.Stop()
					executor.attempts = nil
					manager = newCompactionAffinityManager(t, restarted, executor, model, secondID)
					replayReq, replayOpts = compactionAffinityRequest(model, identity, true, false)
					errRestart := runCompactionAffinityRequest(t, manager, executor, path, replayReq, replayOpts)
					statusErr = nil
					if !errors.As(errRestart, &statusErr) || statusErr.StatusCode() != status {
						t.Errorf("restart error = %v, want original upstream status %d", errRestart, status)
					}
					assertCompactionAffinityOnlyA(t, executor, true)
					if len(executor.attempts) != 1 {
						t.Errorf("restart replay attempts = %#v, want one A attempt", executor.attempts)
					}

					// Recover A without sleeping or reintroducing the explicit session.
					// MarkResult also restores registry availability for the model.
					manager.MarkResult(context.Background(), Result{AuthID: firstID, Provider: executor.provider, Model: model, Success: true})
					executor.failure = nil
					executor.attempts = nil
					replayReq, replayOpts = compactionAffinityRequest(model, identity, true, false)
					if errRecovered := runCompactionAffinityRequest(t, manager, executor, path, replayReq, replayOpts); errRecovered != nil {
						t.Errorf("recovered replay failed: %v", errRecovered)
					}
					assertCompactionAffinityOnlyA(t, executor, true)
					if len(executor.attempts) != 1 {
						t.Errorf("recovered replay attempts = %#v, want one A attempt", executor.attempts)
					}
				})
			}
		}
	}
}

func TestManagerUncompactedAffinityStillAllowsFailover(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		for _, identity := range []string{"prompt_cache_key", "Session-Id"} {
			for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
				t.Run(fmt.Sprintf("%s/%s/%d", path, identity, status), func(t *testing.T) {
					model := "uncompacted-affinity-model"
					firstID := t.Name() + "-a"
					secondID := t.Name() + "-b"
					selector := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: firstID})
					defer selector.Stop()
					executor := &compactionAffinityExecutor{
						provider: "codex", firstID: firstID, bootstrapChunk: path == "stream-bootstrap",
					}
					manager := newCompactionAffinityManager(t, selector, executor, model, secondID)
					req, opts := compactionAffinityRequest(model, identity, false, true)
					if errInitial := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errInitial != nil {
						t.Fatalf("initial conversation failed: %v", errInitial)
					}
					if len(executor.attempts) != 1 || executor.attempts[0].authID != firstID {
						t.Fatalf("initial conversation did not establish A: %#v", executor.attempts)
					}
					executor.attempts = nil
					executor.failure = compactTestStatusError{code: status, msg: "account A temporarily unavailable"}
					req, opts = compactionAffinityRequest(model, identity, false, true)
					if errFailover := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errFailover != nil {
						t.Fatalf("uncompacted failover failed: %v", errFailover)
					}
					if len(executor.attempts) != 2 || executor.attempts[0].authID != firstID || executor.attempts[1].authID != secondID {
						t.Fatalf("uncompacted attempts = %#v, want A then B", executor.attempts)
					}
					for _, call := range executor.attempts {
						if call.pinned != "" {
							t.Errorf("uncompacted request unexpectedly pinned to %q", call.pinned)
						}
					}
				})
			}
		}
	}
}
