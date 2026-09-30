package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/redisqueue"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// Mirrors codexDuplexAffinityError's receiver contract without importing the
// runtime executor (which imports auth): scope, status, and preserved cause.
type receiverDuplexAffinityError struct{ cause error }

func (e *receiverDuplexAffinityError) Error() string         { return e.cause.Error() }
func (e *receiverDuplexAffinityError) Unwrap() error         { return e.cause }
func (e *receiverDuplexAffinityError) IsRequestScoped() bool { return true }
func (e *receiverDuplexAffinityError) StatusCode() int {
	var status interface{ StatusCode() int }
	if errors.As(e.cause, &status) {
		return status.StatusCode()
	}
	return http.StatusConflict
}

func TestManagerStreamReceiverLocalDuplexStopBypassesMatchingCooldownRule(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })
	withEnabledErrorQueue(t)
	subscriber, unsubscribe := redisqueue.SubscribeErrors()
	defer unsubscribe()

	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	hook := &recordingHook{}
	manager := NewManager(nil, origin, hook)
	a := &Auth{ID: "receiver-A", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{
			Status: 503, Match: []string{"session affinity state"}, Action: "stop-and-cooldown",
		}},
	}}
	if _, err := manager.Register(WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	opts := core.Options{Metadata: map[string]any{compactionAffinityStoreMetadataKey: origin}}
	manager.prepareCompactionDuplexValidation(opts)
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	origin.cache.mu.Lock()
	origin.cache.persistenceErr = errors.New("disk unavailable")
	origin.cache.mu.Unlock()
	cause := validate(a.ID, []byte(`{"input":[{"type":"compaction","encrypted_content":"signed-A"}]}`))
	local := &receiverDuplexAffinityError{cause: cause}
	if !IsLocalCompactionAffinityStop(local) || local.StatusCode() != 503 {
		t.Fatalf("callback did not produce wrapped local 503: %v", local)
	}
	if action, ok := matchRequestScopedErrorAction(a, local, manager.runtimeConfigSnapshot()); !ok || action == "" {
		t.Fatal("fixture must match the upstream cooldown rule")
	}
	chunks := make(chan core.StreamChunk, 1)
	chunks <- core.StreamChunk{Err: local}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), a, "codex", "model", "model", nil,
		[]core.StreamChunk{{Payload: []byte(`data: {"type":"response.created"}` + "\n\n")}},
		chunks, OAuthModelAliasResult{}, false, opts)
	var received error
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			received = chunk.Err
		}
	}
	if received != local || !IsLocalCompactionAffinityStop(unwrapExecutionBoundaryError(received)) {
		t.Fatalf("receiver erased local error or downstream retry marker: %v", received)
	}
	if hook.lastResult.Load() != nil {
		t.Fatal("local error published OnResult (including terminal success)")
	}
	select {
	case event := <-subscriber:
		t.Fatalf("local error published error event: %s", event)
	default:
	}
	current, _ := manager.GetByID(a.ID)
	if current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || len(current.ModelStates) != 0 {
		t.Fatalf("local error mutated credential/model state: %+v", current)
	}

	// The same message/status from upstream must still use result policy.
	upstream := customStatusError{code: 503, msg: "session affinity state upstream failure"}
	chunks = make(chan core.StreamChunk, 1)
	chunks <- core.StreamChunk{Err: upstream}
	close(chunks)
	stream = manager.wrapStreamResult(context.Background(), a, "codex", "model", "model", nil, nil,
		chunks, OAuthModelAliasResult{}, false, core.Options{})
	for range stream.Chunks {
	}
	result := hook.lastResult.Load()
	if result == nil || result.Success || result.Error == nil {
		t.Fatal("ordinary upstream 503 bypassed accounting")
	}
	requireErrorSubscriberPayload(t, subscriber)
	current, _ = manager.GetByID(a.ID)
	if !current.Unavailable || current.NextRetryAfter.IsZero() {
		t.Fatal("ordinary matching upstream 503 did not cool credential")
	}
}

func TestManagerStreamReceiverScannerMultilinePreservesUnitsAndRegistersBeforeRelease(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	opts := core.Options{SourceFormat: sdktranslator.FormatOpenAIResponse,
		Metadata: map[string]any{compactionAffinityStoreMetadataKey: origin}}
	units := []string{
		"event: response.output_item.done",
		`data: {"type":"response.output_item.done",`,
		`data: "item":{"type":"compaction","encrypted_content":"receiver-multiline-A"}}`,
	}
	chunks := make(chan core.StreamChunk, len(units)+1)
	for _, unit := range units {
		chunks <- core.StreamChunk{Payload: []byte(unit)}
	}
	upstream := customStatusError{code: 503, msg: "ordinary failure after signed output"}
	chunks <- core.StreamChunk{Err: upstream}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "receiver-multiline-A"},
		"codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, opts)
	key := compactionAffinityKeys(core.Options{OriginalRequest: []byte(`{"input":[{"type":"compaction","encrypted_content":"receiver-multiline-A"}]}`)})[0]
	index := 0
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			if index != len(units) || chunk.Err != upstream {
				t.Fatalf("error arrived before original units: index=%d err=%v", index, chunk.Err)
			}
			continue
		}
		if index >= len(units) || string(chunk.Payload) != units[index] {
			t.Fatalf("unit %d changed, duplicated, or empty: %q", index, chunk.Payload)
		}
		if index > 0 {
			if signer, ok := origin.cache.Get(key); !ok || signer != "receiver-multiline-A" || !origin.cache.IsProtected(key) {
				t.Fatal("signed multiline data released before protected registration")
			}
		}
		index++
	}
	if index != len(units) {
		t.Fatalf("received %d original units, want %d", index, len(units))
	}
}

func TestManagerStreamReceiverOrdinary503BootstrapStillRetries(t *testing.T) {
	selector := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: "receiver-bootstrap-A"})
	defer selector.Stop()
	executor := &compactionAffinityExecutor{
		provider: "codex", firstID: "receiver-bootstrap-A", bootstrapChunk: true,
		failure: customStatusError{code: 503, msg: "ordinary upstream overload"},
	}
	manager := newCompactionAffinityManager(t, selector, executor, "receiver-bootstrap-model", "receiver-bootstrap-B")
	req, opts := compactionAffinityRequest("receiver-bootstrap-model", "none", false, false)
	stream, err := manager.ExecuteStream(context.Background(), []string{"codex"}, req, opts)
	if err != nil || stream == nil {
		t.Fatalf("ordinary bootstrap retry failed: %v", err)
	}
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatalf("ordinary bootstrap retry returned error: %v", chunk.Err)
		}
	}
	if len(executor.attempts) != 2 || executor.attempts[0].authID != executor.firstID || executor.attempts[1].authID != "receiver-bootstrap-B" {
		t.Fatalf("bootstrap attempts = %+v, want A then B", executor.attempts)
	}
}
