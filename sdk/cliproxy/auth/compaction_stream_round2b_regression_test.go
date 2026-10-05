package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type round2BSuccessCancelHook struct {
	NoopHook
	cancel  context.CancelFunc
	results []Result
}

func (h *round2BSuccessCancelHook) OnResult(_ context.Context, result Result) {
	h.results = append(h.results, result)
	if result.Success {
		h.cancel()
	}
}

func TestCompactionStreamRound2BSuccessHookCancellationAccountsOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hook := &round2BSuccessCancelHook{cancel: cancel}
	manager, auth, model := newClaudeCancellationTestManager(t, &claudeCancellationTestExecutor{}, hook)
	stream, err := manager.ExecuteStream(ctx, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		for range stream.Chunks {
		}
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("stream did not close after the success hook canceled its caller")
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("success hook did not cancel the caller")
	}
	if len(hook.results) != 1 || !hook.results[0].Success {
		t.Fatalf("results = %#v, want exactly one success", hook.results)
	}
	requireClaudeCancellationNeutral(t, manager, auth.ID, model)
}

// Exercise the replacement producer created after an error in the 401 bootstrap,
// including both the request-stop return and successful ownership transfer.
func TestCompactionStreamRound2BBootstrapRefreshProducerOwnership(t *testing.T) {
	for _, stop := range []bool{true, false} {
		name := "transfer"
		if stop {
			name = "request-stop"
		}
		t.Run(name, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopErr := &Error{HTTPStatus: http.StatusBadRequest, Message: "round2b-bootstrap-stop"}
			var producers []context.Context
			source := make(chan cliproxyexecutor.StreamChunk, 1)
			executor := &claudeCancellationTestExecutor{}
			executor.streamFn = func(ctx context.Context, _ *Auth) (*cliproxyexecutor.StreamResult, error) {
				producers = append(producers, ctx)
				if len(producers) == 1 {
					chunks := make(chan cliproxyexecutor.StreamChunk, 1)
					chunks <- cliproxyexecutor.StreamChunk{Err: &Error{HTTPStatus: http.StatusUnauthorized, Message: "expired"}}
					close(chunks)
					return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
				}
				if stop {
					source <- cliproxyexecutor.StreamChunk{Err: stopErr}
				} else {
					source <- cliproxyexecutor.StreamChunk{Payload: []byte("first")}
				}
				return &cliproxyexecutor.StreamResult{Chunks: source}, nil
			}
			executor.refreshFn = func(_ context.Context, auth *Auth) (*Auth, error) {
				auth.Metadata["access_token"] = "round2b-refreshed"
				auth.Metadata["request_scoped_errors"] = []internalconfig.RequestScopedErrorRule{{
					Status: http.StatusBadRequest, Match: []string{stopErr.Message}, Action: "stop",
				}}
				return auth, nil
			}
			manager, _, model := newClaudeCancellationTestManager(t, executor, nil)
			stream, err := manager.ExecuteStream(parent, []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
			if executor.refreshCalls.Load() != 1 || len(producers) != 2 {
				t.Fatalf("refreshes=%d producers=%d, want 1/2", executor.refreshCalls.Load(), len(producers))
			}
			if stop {
				if !errors.Is(err, stopErr) || stream != nil {
					t.Fatalf("stream=%#v error=%v, want bootstrap request stop", stream, err)
				}
				// Keep the source open: cancellation must not depend on EOF.
				defer close(source)
			} else {
				if err != nil || stream == nil {
					t.Fatalf("ExecuteStream() = %#v, %v", stream, err)
				}
				if producers[1].Err() != nil {
					t.Fatal("replacement producer canceled before ownership transfer")
				}
				select {
				case chunk := <-stream.Chunks:
					if chunk.Err != nil || string(chunk.Payload) != "first" {
						t.Fatalf("first chunk = %#v", chunk)
					}
				case <-time.After(time.Second):
					t.Fatal("transferred stream did not deliver its first payload")
				}
				close(source)
				select {
				case _, ok := <-stream.Chunks:
					if ok {
						t.Fatal("unexpected chunk after source close")
					}
				case <-time.After(time.Second):
					t.Fatal("transferred stream did not close")
				}
			}
			for i, producer := range producers {
				select {
				case <-producer.Done():
				case <-time.After(time.Second):
					t.Fatalf("producer %d was not canceled", i+1)
				}
			}
			if parent.Err() != nil {
				t.Fatal("producer cancellation canceled the caller")
			}
		})
	}
}
