package auth

import (
	"context"
	"io"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type homePanicExecutorR11 struct {
	homeExecutionExecutor
	selection *HomeDispatchSelection
	attempt   context.Context
	value     any
	retire    bool
}

func (e *homePanicExecutorR11) fail(ctx context.Context, opts cliproxyexecutor.Options) {
	e.selection = opts.ExecutionLifecycle.(*HomeDispatchSelection)
	e.attempt = ctx
	if e.retire {
		e.selection.End("upstream_disconnected")
	}
	panic(e.value)
}

func (e *homePanicExecutorR11) Execute(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.fail(ctx, opts)
	return cliproxyexecutor.Response{}, nil
}

func (e *homePanicExecutorR11) CountTokens(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.fail(ctx, opts)
	return cliproxyexecutor.Response{}, nil
}

func (e *homePanicExecutorR11) ExecuteStream(ctx context.Context, _ *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.fail(ctx, opts)
	return nil, nil
}

// Keep reason: PR #174's panic failure path cannot be reached cheaply by a
// user flow. A leaked hold strands Home capacity even after HTTP panic recovery.
func TestHomeAttemptPanicReleasesHoldR11(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		for _, retire := range []bool{false, true} {
			name := path + "/panic"
			if retire {
				name = path + "/retire_then_panic"
			}
			t.Run(name, func(t *testing.T) {
				manager := NewManager(nil, nil, nil)
				manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
				registry := executionregistry.New()
				t.Cleanup(func() { _ = registry.Close() })
				manager.PublishHomeDispatch(homeExecutionDispatcher{}, registry, 1)
				value := &struct{ message string }{"executor panic"}
				executor := &homePanicExecutorR11{value: value, retire: retire}
				manager.RegisterExecutor(executor)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				req := cliproxyexecutor.Request{Model: "test"}
				providers := []string{"home-execution"}
				var recovered any
				func() {
					defer func() { recovered = recover() }()
					switch path {
					case "stream":
						_, _ = manager.ExecuteStream(ctx, providers, req, cliproxyexecutor.Options{})
					case "count":
						_, _ = manager.ExecuteCount(ctx, providers, req, cliproxyexecutor.Options{})
					default:
						_, _ = manager.Execute(ctx, providers, req, cliproxyexecutor.Options{})
					}
				}()
				if recovered != value {
					t.Fatalf("panic = %v, want original %v", recovered, value)
				}
				if executor.selection == nil {
					t.Fatal("executor never acquired a Home selection")
				}
				executor.selection.streamEndMu.Lock()
				holds := executor.selection.streamEndHolds
				executor.selection.streamEndMu.Unlock()
				if holds != 0 {
					t.Fatalf("terminal holds after panic = %d, want 0", holds)
				}
				if executor.attempt.Err() == nil {
					t.Fatal("panic did not release the attempt context")
				}
				if executor.selection.Active() {
					t.Fatal("panic left the selection active")
				}
				if executor.selection.attemptCancels.Len() != 0 {
					t.Fatal("panic leaked an attempt cancel")
				}
				// Exercise the real Home admission path with capacity one: a follow-up
				// request must acquire the slot that the panicking request owned.
				if path == "stream" {
					chunks := make(chan cliproxyexecutor.StreamChunk, 1)
					chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok")}
					close(chunks)
					manager.RegisterExecutor(&homeExecutionStreamExecutor{chunks: chunks})
					stream, err := manager.ExecuteStream(ctx, providers, req, cliproxyexecutor.Options{})
					if err != nil {
						t.Fatalf("following stream could not acquire slot: %v", err)
					}
					got := 0
					for {
						select {
						case chunk, ok := <-stream.Chunks:
							if !ok {
								if got != 1 {
									t.Fatalf("following stream chunks = %d, want 1", got)
								}
								return
							}
							if chunk.Err != nil && chunk.Err != io.EOF {
								t.Fatal(chunk.Err)
							}
							got++
						case <-ctx.Done():
							t.Fatal("following stream failed to complete: ", ctx.Err())
						}
					}
				}
				manager.RegisterExecutor(&homeExecutionExecutor{})
				if _, err := manager.Execute(ctx, providers, req, cliproxyexecutor.Options{}); err != nil {
					t.Fatalf("following request could not acquire slot: %v", err)
				}
			})
		}
	}
}
