package auth

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// The real execution path must rotate first attempts even when every request
// subsequently retries through every credential with unchanged quota state.
func TestCodexExecutionRetriesPreserveNewSessionRotation(t *testing.T) {
	for _, path := range []string{"execute", "stream", "count"} {
		for _, retryBudget := range []int{0, 2} {
			t.Run(fmt.Sprintf("%s/retries=%d", path, retryBudget), func(t *testing.T) {
				selector := NewSessionAffinitySelector(&RoundRobinSelector{})
				t.Cleanup(selector.Stop)
				manager := NewManager(nil, selector, nil)
				manager.SetRetryConfig(retryBudget, 0, 0)
				model := "rotation-execution-" + t.Name()
				ids := []string{"a-" + model, "b-" + model, "c-" + model}
				for _, id := range ids {
					registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
					metadata := map[string]any{"disable_cooling": true}
					if retryBudget == 0 {
						metadata["request_scoped_errors"] = []internalconfig.RequestScopedErrorRule{{Status: 429, Match: []string{"request-level-limit"}, Action: "continue"}}
					}
					_, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: metadata})
					if err != nil {
						t.Fatal(err)
					}
				}
				var attempts []string
				succeed := false
				execute := func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
					attempts = append(attempts, auth.ID)
					if !succeed {
						status := 429
						if retryBudget > 0 {
							status = 500
						}
						return cliproxyexecutor.Response{}, customStatusError{code: status, msg: "request-level-limit"}
					}
					return cliproxyexecutor.Response{Payload: []byte(auth.ID)}, nil
				}
				manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", mockCustomErrorExecutor: mockCustomErrorExecutor{executeFn: execute, countFn: execute},
					streamFn: func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
						resp, err := execute(ctx, auth, req, opts)
						if err != nil {
							return nil, err
						}
						chunks := make(chan cliproxyexecutor.StreamChunk, 1)
						chunks <- cliproxyexecutor.StreamChunk{Payload: resp.Payload}
						close(chunks)
						return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
					},
				})
				run := func(opts cliproxyexecutor.Options) error {
					if path == "execute" {
						_, err := manager.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts)
						return err
					}
					if path == "count" {
						_, err := manager.ExecuteCount(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts)
						return err
					}
					result, err := manager.ExecuteStream(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, opts)
					if err == nil {
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								return chunk.Err
							}
						}
					}
					return err
				}
				counts := map[string]int{}
				for i := 0; i < 12; i++ {
					attempts = nil
					succeed = false
					opts := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": []string{fmt.Sprintf("execute-session-%d", i)}}}
					if err := run(opts); err == nil {
						t.Fatal("expected upstream 429")
					}
					if len(attempts) != 3*(retryBudget+1) {
						t.Fatalf("attempts = %v, want each credential once per round", attempts)
					}
					counts[attempts[0]]++
					if retryBudget > 0 {
						continue
					} // Credential failures invalidate affinity.
					last := attempts[2]
					attempts = nil
					succeed = true
					if err := run(opts); err != nil {
						t.Fatal(err)
					}
					if len(attempts) != 1 || attempts[0] != last {
						t.Fatalf("existing-session affinity = %v, want %s", attempts, last)
					}
				}
				t.Logf("first-attempt spread: %v", counts)
				for _, id := range ids {
					if counts[id] != 4 {
						t.Fatalf("first-attempt spread = %v, want 4 per account", counts)
					}
				}
			})
		}
	}
}

func TestRoundRobinRetryDoesNotEvictInitialCursors(t *testing.T) {
	selector := &RoundRobinSelector{maxKeys: 1}
	auths := []*Auth{{ID: "a"}, {ID: "b"}}
	pick := func(ctx context.Context, model string) *Auth {
		t.Helper()
		a, err := selector.Pick(ctx, "codex", model, cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	if got := pick(context.Background(), "initial"); got.ID != "a" {
		t.Fatal(got.ID)
	}
	pick(withSelectionRetry(context.Background()), "unseen-retry-model")
	if got := pick(context.Background(), "initial"); got.ID != "b" {
		t.Fatalf("retry evicted initial cursor: %s", got.ID)
	}
}

func TestCodexRotationSkipsCoolingAndBelowFloor(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	defer selector.Stop()
	now := time.Now()
	auths := []*Auth{
		{ID: "a-cooling", Provider: "codex", Unavailable: true, NextRetryAfter: now.Add(time.Hour)},
		{ID: "b-below-floor", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Used-Percent": "98", "X-Codex-Primary-Reset-After-Seconds": "3600"}}},
		{ID: "c-healthy", Provider: "codex"},
		{ID: "d-healthy", Provider: "codex"},
	}
	counts := map[string]int{}
	for i := 0; i < 12; i++ {
		opts := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": []string{fmt.Sprintf("eligible-session-%d", i)}}}
		a, err := selector.Pick(context.Background(), "mixed", "model", opts, auths)
		if err != nil {
			t.Fatal(err)
		}
		counts[a.ID]++
	}
	if counts["c-healthy"] != 6 || counts["d-healthy"] != 6 || len(counts) != 2 {
		t.Fatalf("eligible spread = %v, want 6/6 healthy only", counts)
	}
}

func TestCodexNewSessionsRotate(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, retryTraffic := range []bool{false, true} {
			t.Run(fmt.Sprintf("mixed=%v/retry=%v", mixed, retryTraffic), func(t *testing.T) {
				selector := NewSessionAffinitySelector(&RoundRobinSelector{})
				defer selector.Stop()
				manager := NewManager(nil, selector, nil)
				manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "codex"})
				model := "codex-rotation-" + t.Name()
				ids := []string{"codex-a-" + t.Name(), "codex-b-" + t.Name(), "codex-c-" + t.Name()}
				for _, id := range ids {
					registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
					_, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive, Quota: QuotaState{ObservedAt: time.Now(), Signals: map[string]string{"X-Codex-Primary-Used-Percent": "50", "X-Codex-Primary-Reset-After-Seconds": "3600"}}})
					if err != nil {
						t.Fatal(err)
					}
				}
				counts := map[string]int{}
				for i := 0; i < 12; i++ {
					if retryTraffic {
						// An existing session retries after the first two credentials were
						// attempted. Even with equal quota state, this singleton pick
						// must not reset the cursor for independent new sessions.
						selector.cache.Set("mixed::codex:existing::"+model, ids[0])
						selector.cache.Set("codex::codex:existing::"+model, ids[0])
						warm := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": []string{"existing"}}}
						tried := map[string]struct{}{ids[0]: {}, ids[1]: {}}
						if mixed {
							_, _, _, err := manager.pickNextMixed(context.Background(), []string{"codex"}, model, warm, tried)
							if err != nil {
								t.Fatal(err)
							}
						} else {
							_, _, err := manager.pickNext(context.Background(), "codex", model, warm, tried)
							if err != nil {
								t.Fatal(err)
							}
						}
					}
					opts := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": []string{fmt.Sprintf("new-session-%d", i)}}}
					pick := func() (*Auth, error) {
						if mixed {
							a, _, _, e := manager.pickNextMixed(context.Background(), []string{"codex"}, model, opts, nil)
							return a, e
						}
						return manager.SelectAuth(context.Background(), "codex", model, opts)
					}
					a, e := pick()
					if e != nil {
						t.Fatal(e)
					}
					counts[a.ID]++
					again, e := pick()
					if e != nil || again.ID != a.ID {
						t.Fatalf("affinity changed: %v %v", again, e)
					}
				}
				t.Logf("new-session spread: %v", counts)
				for _, id := range ids {
					if counts[id] != 4 {
						t.Errorf("new-session spread %v; want 4 per account", counts)
						break
					}
				}
			})
		}
	}
}
