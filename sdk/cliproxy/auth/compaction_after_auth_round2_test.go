package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type round2SelectedA struct{ id string }

func (s round2SelectedA) Pick(_ context.Context, _, _ string, _ core.Options, candidates []*auth.Auth) (*auth.Auth, error) {
	for _, candidate := range candidates {
		if candidate.ID == s.id {
			return candidate, nil
		}
	}
	return candidates[0], nil
}

type round2DispatchReceipt struct {
	auth.ProviderExecutor
	calls atomic.Int32
}

func (e *round2DispatchReceipt) Execute(ctx context.Context, a *auth.Auth, req core.Request, opts core.Options) (core.Response, error) {
	e.calls.Add(1)
	return e.ProviderExecutor.Execute(ctx, a, req, opts)
}

func (e *round2DispatchReceipt) ExecuteStream(ctx context.Context, a *auth.Auth, req core.Request, opts core.Options) (*core.StreamResult, error) {
	e.calls.Add(1)
	return e.ProviderExecutor.ExecuteStream(ctx, a, req, opts)
}

func (e *round2DispatchReceipt) CountTokens(ctx context.Context, a *auth.Auth, req core.Request, opts core.Options) (core.Response, error) {
	e.calls.Add(1)
	return e.ProviderExecutor.CountTokens(ctx, a, req, opts)
}

type round2ResultReceipt struct {
	auth.NoopHook
	results atomic.Int32
}

func (h *round2ResultReceipt) OnResult(context.Context, auth.Result) { h.results.Add(1) }

func round2Body(capsule string) []byte {
	if capsule == "" {
		return []byte(`{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`)
	}
	return []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":%q}],"prompt_cache_key":"replacement-child"}`, capsule))
}

func round2Run(ctx context.Context, m *auth.Manager, path, model string, opts core.Options) error {
	req := core.Request{Model: model, Payload: opts.OriginalRequest}
	switch path {
	case "execute":
		_, err := m.Execute(ctx, []string{"codex"}, req, opts)
		return err
	case "count":
		_, err := m.ExecuteCount(ctx, []string{"codex"}, req, opts)
		return err
	default:
		opts.Stream = true
		stream, err := m.ExecuteStream(ctx, []string{"codex"}, req, opts)
		if err != nil {
			return err
		}
		if stream == nil {
			return fmt.Errorf("nil stream")
		}
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				err = chunk.Err
			}
		}
		return err
	}
}

// Signer evidence is produced by the real Codex HTTP executor and observed at
// a controlled upstream socket. This is plumbing proof, not provider acceptance.
func round2AfterAuthCase(t *testing.T, path, initial, replacement string, negative, reject bool) {
	t.Helper()
	ctx := context.Background()
	a, b, model := t.Name()+"-A", t.Name()+"-B", "gpt-5"
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		capsule := "signed-A"
		if r.Header.Get("Authorization") == "Bearer fixture-B" {
			capsule = "signed-B"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture-response\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-5\",\"output\":[{\"type\":\"compaction\",\"encrypted_content\":%q}],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n", capsule)
	}))
	defer server.Close()
	origin := auth.NewSessionAffinitySelector(round2SelectedA{id: a})
	defer origin.Stop()
	hook := &round2ResultReceipt{}
	m := auth.NewManager(nil, origin, hook)
	m.SetRetryConfig(0, 0, 0)
	e := &round2DispatchReceipt{ProviderExecutor: runtimeexecutor.NewCodexExecutor(&config.Config{})}
	m.RegisterExecutor(e)
	for i, id := range []string{a, b} {
		key := []string{"fixture-A", "fixture-B"}[i]
		_, err := m.Register(ctx, &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": key, "base_url": server.URL}})
		if err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		defer registry.GetGlobalRegistry().UnregisterClient(id)
		opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: round2Body(""), Metadata: map[string]any{core.PinnedAuthMetadataKey: id}}
		if err := round2Run(ctx, m, "execute", model, opts); err != nil {
			t.Fatalf("produce %s via real upstream: %v", id, err)
		}
	}
	if writes.Load() != 2 {
		t.Fatalf("production receipts = %d, want two real HTTP writes", writes.Load())
	}
	opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: round2Body(initial), Headers: http.Header{"Session-Id": []string{"initial-parent"}}}
	if negative {
		m.SetSelector(round2SelectedA{id: a})
		var err error
		opts, err = m.PrepareCompactionRequest(model, opts, ctx)
		if err != nil {
			t.Fatal(err)
		}
		m.SetSelector(origin)
	}
	var intercepted atomic.Int32
	var interceptedMetadata map[string]any
	var canonicalBefore, parentBefore any
	opts.RequestAfterAuthInterceptor = func(_ context.Context, in core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		intercepted.Add(1)
		interceptedMetadata = in.Metadata
		canonicalBefore = in.Metadata[core.CanonicalSessionIDMetadataKey]
		parentBefore = in.Metadata[core.ParentSessionIDMetadataKey]
		if selected, _ := in.Metadata[core.SelectedAuthMetadataKey].(string); selected != a {
			t.Errorf("selected auth = %q, want A", selected)
		}
		return core.RequestAfterAuthInterceptResponse{Body: round2Body(replacement), ClearHeaders: []string{"Session-Id"}, Headers: http.Header{"Session-Id": []string{"replacement-child"}, "X-Parent-Session-Id": []string{"replacement-parent"}}}
	}
	before := make(map[string]*auth.Auth, 2)
	for _, id := range []string{a, b} {
		before[id], _ = m.GetByID(id)
	}
	writes.Store(0)
	e.calls.Store(0)
	hook.results.Store(0)
	err := round2Run(ctx, m, path, model, opts)
	if intercepted.Load() != 1 {
		t.Fatalf("interceptor calls = %d, want one after selecting A", intercepted.Load())
	}
	if reject {
		if interceptedMetadata[core.CanonicalSessionIDMetadataKey] != canonicalBefore || interceptedMetadata[core.ParentSessionIDMetadataKey] != parentBefore {
			t.Error("rejected replacement rederived session hierarchy before signer admission")
		}
		if !auth.IsLocalCompactionAffinityStop(err) {
			t.Errorf("replacement error = %v, want typed local compaction stop", err)
		}
		var local *auth.Error
		if !errors.As(err, &local) || local.StatusCode() != http.StatusConflict {
			t.Errorf("replacement error = %v, want local 409", err)
		}
		if e.calls.Load() != 0 || writes.Load() != 0 || hook.results.Load() != 0 {
			t.Errorf("rejected replacement dispatched/accounted: executor=%d upstream=%d results=%d", e.calls.Load(), writes.Load(), hook.results.Load())
		}
		for _, id := range []string{a, b} {
			current, _ := m.GetByID(id)
			if current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || !reflect.DeepEqual(current.ModelStates, before[id].ModelStates) {
				t.Errorf("local rejection changed account %s: %+v", id, current)
			}
		}
		return
	}
	if err != nil {
		t.Fatalf("allowed replacement: %v", err)
	}
	if e.calls.Load() != 1 || (path != "count" && writes.Load() != 1) {
		t.Fatalf("allowed dispatch receipts: executor=%d upstream=%d", e.calls.Load(), writes.Load())
	}
}

func TestCompactionAfterAuthRound2RejectsSelectedSignerMismatch(t *testing.T) {
	for _, path := range []string{"execute", "stream", "count"} {
		for _, c := range []struct{ name, initial, replacement string }{
			{"known-B", "", "signed-B"},
			{"unknown", "", "unknown-capsule"},
			{"pinned-A-to-B", "signed-A", "signed-B"},
		} {
			t.Run(path+"/"+c.name, func(t *testing.T) {
				round2AfterAuthCase(t, path, c.initial, c.replacement, false, true)
			})
		}
	}
}

func TestCompactionAfterAuthRound2AllowsSameSignerOrdinaryAndNegativeOrigin(t *testing.T) {
	for _, path := range []string{"execute", "stream", "count"} {
		for _, name := range []string{"same-A", "ordinary", "negative-origin"} {
			t.Run(path+"/"+name, func(t *testing.T) {
				replacement := "signed-A"
				if name == "ordinary" {
					replacement = ""
				} else if strings.HasPrefix(name, "negative") {
					replacement = "unknown-capsule"
				}
				round2AfterAuthCase(t, path, "", replacement, name == "negative-origin", false)
			})
		}
	}
}

// The only wrapper behavior is receipt counting and an explicit test header.
// Payload translation, credential injection and socket writes use CodexExecutor.
type round2CreditsHTTPExecutor struct {
	auth.ProviderExecutor
	credits atomic.Int32
}

func (*round2CreditsHTTPExecutor) Identifier() string { return "antigravity" }

func (e *round2CreditsHTTPExecutor) creditOptions(ctx context.Context, opts core.Options) core.Options {
	if auth.AntigravityCreditsRequested(ctx) {
		e.credits.Add(1)
		opts.Headers = opts.Headers.Clone()
		if opts.Headers == nil {
			opts.Headers = make(http.Header)
		}
		opts.Headers.Set("X-Fixture-Credits", "true")
	}
	return opts
}

func (e *round2CreditsHTTPExecutor) Execute(ctx context.Context, a *auth.Auth, req core.Request, opts core.Options) (core.Response, error) {
	return e.ProviderExecutor.Execute(ctx, a, req, e.creditOptions(ctx, opts))
}

func (e *round2CreditsHTTPExecutor) ExecuteStream(ctx context.Context, a *auth.Auth, req core.Request, opts core.Options) (*core.StreamResult, error) {
	return e.ProviderExecutor.ExecuteStream(ctx, a, req, e.creditOptions(ctx, opts))
}

type round2HomeDispatch struct{ selected *auth.Auth }

func (*round2HomeDispatch) HeartbeatOK() bool { return true }
func (*round2HomeDispatch) AbortAmbiguousDispatch() {}
func (d *round2HomeDispatch) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	return json.Marshal(d.selected)
}

type round2HomeResult struct {
	auth.NoopHook
	onResult func()
	calls    int
}

func (h *round2HomeResult) OnResult(context.Context, auth.Result) {
	h.calls++
	if h.onResult != nil {
		h.onResult()
	}
}

func TestCompactionAfterAuthRound2HomeCapturedOriginOutput(t *testing.T) {
	for _, mode := range []string{"positive", "negative", "save-failure", "positive-rewrite", "negative-rewrite"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			a, model := t.Name()+"-A", "gpt-5"
			var writes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writes.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture\",\"status\":\"completed\",\"model\":\"gpt-5\",\"output\":[{\"type\":\"compaction\",\"encrypted_content\":\"home-produced\"}]}}\n\n"))
			}))
			defer server.Close()
			statePath := filepath.Join(t.TempDir(), "affinity.json")
			origin := auth.NewSessionAffinitySelectorWithConfig(auth.SessionAffinityConfig{Fallback: round2SelectedA{id: a}, StatePath: statePath})
			defer origin.Stop()
			hook := &round2HomeResult{}
			m := auth.NewManager(nil, origin, hook)
			cfg := &config.Config{}
			cfg.Home.Enabled = strings.HasPrefix(mode, "negative")
			m.SetConfig(cfg)
			m.SetRetryConfig(0, 0, 0)
			opts, err := m.PrepareCompactionRequest(model, core.Options{SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: round2Body("")}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			cfg = &config.Config{}
			cfg.Home.Enabled = true
			m.SetConfig(cfg)
			m.RegisterExecutor(runtimeexecutor.NewCodexExecutor(cfg))
			dispatch := &round2HomeDispatch{selected: &auth.Auth{ID: a, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "fixture-A", "base_url": server.URL}}}
			m.PublishHomeDispatch(dispatch, executionregistry.New(), 1)
			if strings.HasSuffix(mode, "rewrite") {
				opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
					return core.RequestAfterAuthInterceptResponse{Body: round2Body("home-imported-unknown")}
				}
			}
			if mode == "save-failure" {
				if err := os.Mkdir(statePath, 0700); err != nil {
					t.Fatal(err)
				}
			}
			hook.onResult = func() {
				replay := opts
				replay.OriginalRequest = round2Body("home-produced")
				prepared, err := m.PrepareCompactionRequest(model, replay, ctx)
				if err != nil {
					t.Errorf("Home output reported before signer registration: %v", err)
				}
				pinned, _ := prepared.Metadata[core.PinnedAuthMetadataKey].(string)
				if (mode == "positive" && pinned != a) || (strings.HasPrefix(mode, "negative") && pinned != "") {
					t.Errorf("Home output origin %s pin=%q", mode, pinned)
				}
			}
			response, err := m.Execute(ctx, []string{"codex"}, core.Request{Model: model, Payload: opts.OriginalRequest}, opts)
			wantWrites := int32(1)
			if mode == "positive-rewrite" {
				wantWrites = 0
			}
			if writes.Load() != wantWrites {
				t.Fatalf("Home HTTP receipts=%d, want %d", writes.Load(), wantWrites)
			}
			if mode == "save-failure" || mode == "positive-rewrite" {
				if !auth.IsLocalCompactionAffinityStop(err) || len(response.Payload) != 0 || response.Headers != nil || hook.calls != 0 {
					t.Fatalf("Home save refusal: response=%+v err=%v reports=%d", response, err, hook.calls)
				}
			} else if err != nil || len(response.Payload) == 0 || hook.calls != 1 {
				t.Fatalf("Home output: err=%v payload=%s reports=%d", err, response.Payload, hook.calls)
			}
		})
	}
}

func TestCompactionAfterAuthRound2CreditsStopsBeforeFailover(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		for _, replacement := range []string{"signed-B", "unknown-capsule", "ordinary"} {
			t.Run(path+"/"+replacement, func(t *testing.T) {
				ctx := context.Background()
				a, b := t.Name()+"-A", t.Name()+"-B"
				model := "claude-sonnet-4-6"
				var exhausted atomic.Bool
				var creditWrites atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					isB := r.Header.Get("Authorization") == "Bearer fixture-B"
					if exhausted.Load() {
						if r.Header.Get("X-Fixture-Credits") != "true" {
							w.WriteHeader(http.StatusTooManyRequests)
							_, _ = w.Write([]byte(`{"error":{"message":"normal quota exhausted"}}`))
							return
						}
						creditWrites.Add(1)
						if !isB {
							w.WriteHeader(http.StatusServiceUnavailable)
							_, _ = w.Write([]byte(`{"error":{"message":"ordinary credits A failure"}}`))
							return
						}
					}
					capsule := "signed-A"
					if isB {
						capsule = "signed-B"
					}
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"fixture\",\"status\":\"completed\",\"model\":%q,\"output\":[{\"type\":\"compaction\",\"encrypted_content\":%q}]}}\n\n", model, capsule)
				}))
				defer server.Close()
				origin := auth.NewSessionAffinitySelector(round2SelectedA{id: a})
				defer origin.Stop()
				m := auth.NewManager(nil, origin, nil)
				cfg := &config.Config{}
				cfg.QuotaExceeded.AntigravityCredits = true
				m.SetConfig(cfg)
				m.SetRetryConfig(0, 0, 0)
				e := &round2CreditsHTTPExecutor{ProviderExecutor: runtimeexecutor.NewCodexExecutor(cfg)}
				m.RegisterExecutor(e)
				for i, id := range []string{a, b} {
					_, err := m.Register(ctx, &auth.Auth{ID: id, Provider: "antigravity", Status: auth.StatusActive, Attributes: map[string]string{"api_key": []string{"fixture-A", "fixture-B"}[i], "base_url": server.URL, "header:X-Fixture-Credits": "$X-Fixture-Credits"}})
					if err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(id, "antigravity", []*registry.ModelInfo{{ID: model}})
					defer registry.GetGlobalRegistry().UnregisterClient(id)
					opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: round2Body(""), Metadata: map[string]any{core.PinnedAuthMetadataKey: id}}
					if _, err := m.Execute(ctx, []string{"antigravity"}, core.Request{Model: model, Payload: opts.OriginalRequest}, opts); err != nil {
						t.Fatalf("produce signer via HTTP: %v", err)
					}
				}
				exhausted.Store(true)
				var hookCalls atomic.Int32
				opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: round2Body("")}
				opts.RequestAfterAuthInterceptor = func(hookCtx context.Context, _ core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
					if !auth.AntigravityCreditsRequested(hookCtx) {
						return core.RequestAfterAuthInterceptResponse{}
					}
					hookCalls.Add(1)
					if replacement == "ordinary" {
						return core.RequestAfterAuthInterceptResponse{Body: round2Body("")}
					}
					return core.RequestAfterAuthInterceptResponse{Body: round2Body(replacement)}
				}
				req := core.Request{Model: model, Payload: opts.OriginalRequest}
				var err error
				if path == "execute" {
					_, err = m.Execute(ctx, []string{"antigravity"}, req, opts)
				} else {
					opts.Stream = true
					var stream *core.StreamResult
					stream, err = m.ExecuteStream(ctx, []string{"antigravity"}, req, opts)
					if err == nil && stream != nil {
						for chunk := range stream.Chunks {
							if chunk.Err != nil {
								err = chunk.Err
							}
						}
					}
				}
				if replacement == "ordinary" {
					if err != nil || hookCalls.Load() != 2 || e.credits.Load() != 2 || creditWrites.Load() != 2 {
						t.Fatalf("ordinary credits failover: err=%v hooks=%d executor=%d HTTP=%d", err, hookCalls.Load(), e.credits.Load(), creditWrites.Load())
					}
				} else if !auth.IsLocalCompactionAffinityStop(err) || hookCalls.Load() != 1 || e.credits.Load() != 0 || creditWrites.Load() != 0 {
					t.Fatalf("credits refusal swallowed/dispatched: err=%v hooks=%d executor=%d HTTP=%d", err, hookCalls.Load(), e.credits.Load(), creditWrites.Load())
				}
			})
		}
	}
}
