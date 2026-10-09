package auth

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexCappedRetryRoundsProgress(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		for _, cached := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cached=%v", path, cached), func(t *testing.T) {
				rr := &RoundRobinSelector{}
				selector := NewSessionAffinitySelector(rr)
				t.Cleanup(selector.Stop)
				manager := NewManager(nil, selector, nil)
				manager.SetRetryConfig(2, 0, 1)
				model := "capped-" + t.Name()
				for _, id := range []string{"a", "b", "c"} {
					registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
					t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
					if _, err := manager.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}}); err != nil {
						t.Fatal(err)
					}
				}
				opts := cliproxyexecutor.Options{Headers: http.Header{"Session-Id": {"capped-session"}}}
				if cached {
					// A cached first attempt bypasses RoundRobin.Pick. Retry progress
					// must still start after that credential, not after the shared cursor.
					selector.cache.Set("mixed::codex:capped-session::"+model, "a")
					rr.lastPicked = map[string]string{"mixed:" + model: "c"}
				}
				var attempts []string
				execute := func(_ context.Context, a *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
					attempts = append(attempts, a.ID)
					if a.ID != "c" {
						return cliproxyexecutor.Response{}, customStatusError{code: 500, msg: "ordinary upstream failure"}
					}
					return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
				}
				manager.RegisterExecutor(&customStreamMockExecutor{identifier: "codex", mockCustomErrorExecutor: mockCustomErrorExecutor{executeFn: execute, countFn: execute},
					streamFn: func(ctx context.Context, a *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
						resp, err := execute(ctx, a, req, opts)
						if err != nil {
							return nil, err
						}
						chunks := make(chan cliproxyexecutor.StreamChunk, 1)
						chunks <- cliproxyexecutor.StreamChunk{Payload: resp.Payload}
						close(chunks)
						return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
					},
				})
				var err error
				req := cliproxyexecutor.Request{Model: model}
				switch path {
				case "execute":
					_, err = manager.Execute(context.Background(), []string{"codex"}, req, opts)
				case "count":
					_, err = manager.ExecuteCount(context.Background(), []string{"codex"}, req, opts)
				case "stream":
					var result *cliproxyexecutor.StreamResult
					result, err = manager.ExecuteStream(context.Background(), []string{"codex"}, req, opts)
					if err == nil {
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								err = chunk.Err
							}
						}
					}
				}
				if err != nil || !reflect.DeepEqual(attempts, []string{"a", "b", "c"}) {
					t.Fatalf("attempts=%v error=%v; want a -> b -> c and success", attempts, err)
				}
				wantCursor := "a"
				if cached {
					wantCursor = "c"
				}
				if got := rr.lastPicked["mixed:"+model]; got != wantCursor {
					t.Fatalf("initial cursor=%q, want unchanged %q", got, wantCursor)
				}
				t.Logf("attempts=%v; initial cursor=%s", attempts, wantCursor)
			})
		}
	}
}

func TestCodexAffinityFailoverIsFair(t *testing.T) {
	for _, affinity := range []string{"explicit", "lcp"} {
		for _, unavailable := range []string{"cooldown", "quota"} {
			t.Run(affinity+"/"+unavailable, func(t *testing.T) {
				rr := &RoundRobinSelector{}
				selector := NewSessionAffinitySelector(rr)
				t.Cleanup(selector.Stop)
				auths := []*Auth{{ID: "a", Provider: "codex"}, {ID: "b", Provider: "codex"}, {ID: "c", Provider: "codex"}}
				options := func(i int) cliproxyexecutor.Options {
					if affinity == "explicit" {
						return cliproxyexecutor.Options{Headers: http.Header{"Session-Id": {fmt.Sprintf("existing-%d", i)}}}
					}
					return cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, OriginalRequest: []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"distinct conversation %d"}]}`, i)), Metadata: map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "fixture-caller"}}
				}
				for i := 0; i < 12; i++ {
					if a, err := selector.Pick(context.Background(), "codex", "model", options(i), auths[:1]); err != nil || a.ID != "a" {
						t.Fatalf("seed binding: %v %v", a, err)
					}
				}
				// Establish a stable initial cursor at c without modifying bindings.
				for i := 0; i < 2; i++ {
					if _, err := rr.Pick(context.Background(), "codex", "model", cliproxyexecutor.Options{}, auths); err != nil {
						t.Fatal(err)
					}
				}
				if rr.lastPicked["codex:model"] != "c" {
					t.Fatal("fixture did not establish initial cursor c")
				}
				now := time.Now()
				if unavailable == "cooldown" {
					auths[0].Unavailable = true
					auths[0].NextRetryAfter = now.Add(time.Hour)
				} else {
					auths[0].Quota = QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-After-Seconds": "3600"}}
				}
				counts := map[string]int{}
				for i := 0; i < 12; i++ {
					opts := options(i)
					a, err := selector.Pick(context.Background(), "codex", "model", opts, auths)
					if err != nil {
						t.Fatal(err)
					}
					counts[a.ID]++
					selector.OnResult(Result{AuthID: a.ID, Provider: "codex", Model: "model", Success: true, Options: opts})
					again, err := selector.Pick(context.Background(), "codex", "model", options(i), auths)
					if err != nil || again.ID != a.ID {
						t.Fatalf("replacement affinity changed: %v %v", again, err)
					}
				}
				if counts["b"] != 6 || counts["c"] != 6 || len(counts) != 2 {
					t.Fatalf("failover spread=%v, want b/c=6/6", counts)
				}
				if rr.lastPicked["codex:model"] != "c" {
					t.Fatal("failovers moved initial cursor")
				}
				t.Logf("failover spread=%v; initial cursor=c; replacement affinity stable", counts)
			})
		}
	}
}
