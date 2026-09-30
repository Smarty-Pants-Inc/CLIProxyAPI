package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// Exercise the public dispatch boundary, not the termination predicate alone.
// These tests use the base executor/interceptor API and need no provider access.
type terminalRound3Executor struct {
	ProviderExecutor
	calls []string
	failA bool
}

func (*terminalRound3Executor) Identifier() string { return "codex" }
func (e *terminalRound3Executor) Execute(_ context.Context, a *Auth, _ core.Request, _ core.Options) (core.Response, error) {
	e.calls = append(e.calls, a.ID)
	return core.Response{Payload: []byte(`{"ok":true}`)}, nil
}
func (e *terminalRound3Executor) CountTokens(ctx context.Context, a *Auth, req core.Request, opts core.Options) (core.Response, error) {
	return e.Execute(ctx, a, req, opts)
}
func (e *terminalRound3Executor) ExecuteStream(_ context.Context, a *Auth, _ core.Request, _ core.Options) (*core.StreamResult, error) {
	e.calls = append(e.calls, a.ID)
	if e.failA && len(e.calls) == 1 {
		return nil, &Error{Code: "upstream_unavailable", Message: "ordinary upstream failure", HTTPStatus: http.StatusServiceUnavailable}
	}
	chunks := make(chan core.StreamChunk, 1)
	chunks <- core.StreamChunk{Payload: []byte("data: {\"ok\":true}\n\n")}
	close(chunks)
	return &core.StreamResult{Chunks: chunks}, nil
}

type terminalRound3Selector struct{ first string }

func (s terminalRound3Selector) Pick(_ context.Context, _, _ string, _ core.Options, candidates []*Auth) (*Auth, error) {
	for _, a := range candidates {
		if a.ID == s.first {
			return a, nil
		}
	}
	return candidates[0], nil
}

type terminalRound3Hook struct {
	NoopHook
	results int
}

func (h *terminalRound3Hook) OnResult(context.Context, Result) { h.results++ }

func terminalRound3Manager(t *testing.T) (*Manager, *terminalRound3Executor, *terminalRound3Hook, []string, string) {
	t.Helper()
	ids := []string{t.Name() + "-A", t.Name() + "-B"}
	model := "terminal-round3-model"
	hook := &terminalRound3Hook{}
	m := NewManager(nil, terminalRound3Selector{first: ids[0]}, hook)
	m.SetRetryConfig(0, 0, 0)
	e := &terminalRound3Executor{}
	m.RegisterExecutor(e)
	for _, id := range ids {
		if _, err := m.Register(context.Background(), &Auth{ID: id, Provider: "codex", Status: StatusActive}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
	return m, e, hook, ids, model
}

func terminalRound3Run(ctx context.Context, m *Manager, path, model string, opts core.Options) error {
	req := core.Request{Model: model, Payload: opts.OriginalRequest}
	switch path {
	case "execute":
		_, err := m.Execute(ctx, []string{"codex"}, req, opts)
		return err
	case "count":
		_, err := m.ExecuteCount(ctx, []string{"codex"}, req, opts)
		return err
	default:
		stream, err := m.ExecuteStream(ctx, []string{"codex"}, req, opts)
		if err != nil {
			return err
		}
		if stream == nil {
			return fmt.Errorf("nil stream")
		}
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				return chunk.Err
			}
		}
		return nil
	}
}

func TestCompactionTerminalRound3PreservesFirstDirectResponse(t *testing.T) {
	for _, path := range []string{"stream", "execute", "count"} {
		for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
			for _, laterTerminates := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%d/later-terminal-%t", path, status, laterTerminates), func(t *testing.T) {
					m, e, hook, ids, model := terminalRound3Manager(t)
					before := make(map[string]*Auth)
					for _, id := range ids {
						before[id], _ = m.GetByID(id)
					}
					calls := 0
					body := []byte("original plugin response\n")
					headers := http.Header{"Content-Type": {"text/plain"}, "Retry-After": {"7"}, "X-Terminal": {"first", "retained"}}
					opts := core.Options{Stream: path == "stream", SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: []byte(`{"input":[]}`)}
					opts.RequestAfterAuthInterceptor = func(_ context.Context, in core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
						calls++
						if calls == 1 {
							if in.Metadata[core.SelectedAuthMetadataKey] != ids[0] {
								t.Errorf("first selected account = %v", in.Metadata[core.SelectedAuthMetadataKey])
							}
							return core.RequestAfterAuthInterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: headers, ResponseBody: body}
						}
						return core.RequestAfterAuthInterceptResponse{Terminate: laterTerminates, StatusCode: http.StatusForbidden, ResponseHeaders: http.Header{"X-Terminal": {"replacement"}}, ResponseBody: []byte("later response")}
					}
					ctx := context.Background()
					err := terminalRound3Run(ctx, m, path, model, opts)
					var direct *core.RequestTerminatedError
					if !errors.As(err, &direct) {
						t.Errorf("error = %T %v, want original direct response", err, err)
					} else if direct.StatusCode() != status || !reflect.DeepEqual(direct.ResponseHeaders(), headers) || string(direct.ResponseBody()) != string(body) {
						t.Errorf("direct response replaced: %+v", direct)
					}
					if calls != 1 || len(e.calls) != 0 || hook.results != 0 {
						t.Errorf("hook=%d executor=%v results=%d, want 1/none/0", calls, e.calls, hook.results)
					}
					if ctx.Err() != nil {
						t.Errorf("caller canceled: %v", ctx.Err())
					}
					for _, id := range ids {
						a, _ := m.GetByID(id)
						if a.Unavailable || !a.NextRetryAfter.IsZero() || a.LastError != nil || !reflect.DeepEqual(a.ModelStates, before[id].ModelStates) {
							t.Errorf("terminal response changed account availability: %+v", a)
						}
					}
				})
			}
		}
	}
}

// A missing plugin must not bypass actual-account admission. In particular,
// captured-positive Home/credits dispatch does not necessarily call Pick.
func TestCompactionTerminalRound3NoInterceptorStillValidatesSelectedAuth(t *testing.T) {
	for _, control := range []string{"same-signer", "wrong-signer", "canceled", "negative-origin", "legacy-no-selected-id"} {
		t.Run(control, func(t *testing.T) {
			origin := NewSessionAffinitySelector(terminalRound3Selector{first: "A"})
			defer origin.Stop()
			if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"nil-hook-signed-A"}]}`)); err != nil {
				t.Fatal(err)
			}
			m := NewManager(nil, origin, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := []byte(`{"input":[{"type":"compaction","encrypted_content":"nil-hook-signed-A"}]}`)
			opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: body}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			selected := []string{"A"}
			if control == "wrong-signer" {
				selected[0] = "B"
			}
			if control == "canceled" {
				cancel()
			}
			if control == "negative-origin" {
				opts.Metadata[compactionAffinityStoreMetadataKey] = (*SessionAffinitySelector)(nil)
				selected[0] = "B"
			}
			if control == "legacy-no-selected-id" {
				selected = nil
			}
			req := core.Request{Model: "model", Payload: body}
			finalReq, finalOpts, err := applyRequestAfterAuthInterceptor(ctx, nil, "codex", req, opts, "model", selected...)
			if control == "wrong-signer" {
				var local *Error
				if !IsLocalCompactionAffinityStop(err) || !errors.As(err, &local) || local.StatusCode() != http.StatusConflict {
					t.Errorf("nil-hook mismatch error=%v, want typed local 409", err)
				}
			} else if control == "canceled" {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("nil-hook cancellation error=%v", err)
				}
			} else if err != nil {
				t.Errorf("allowed nil-hook control %s: %v", control, err)
			}
			if !reflect.DeepEqual(finalReq, req) || string(finalOpts.OriginalRequest) != string(body) {
				t.Error("nil-hook admission rewrote original request")
			}
		})
	}
}

func TestCompactionTerminalRound3OrdinaryUpstreamStillFailsOver(t *testing.T) {
	m, e, _, ids, model := terminalRound3Manager(t)
	e.failA = true
	var selected []string
	opts := core.Options{Stream: true, SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: []byte(`{"input":[]}`)}
	opts.RequestAfterAuthInterceptor = func(_ context.Context, in core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
		selected = append(selected, in.Metadata[core.SelectedAuthMetadataKey].(string))
		return core.RequestAfterAuthInterceptResponse{}
	}
	if err := terminalRound3Run(context.Background(), m, "stream", model, opts); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.calls, ids) || !reflect.DeepEqual(selected, ids) {
		t.Fatalf("ordinary retry executor=%v hooks=%v, want A then B=%v", e.calls, selected, ids)
	}
}

type terminalRound3HomeDispatcher struct {
	calls   int
	payload []byte
}

func (*terminalRound3HomeDispatcher) HeartbeatOK() bool       { return true }
func (*terminalRound3HomeDispatcher) AbortAmbiguousDispatch() {}
func (d *terminalRound3HomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	d.calls++
	if d.calls > 1 {
		return nil, errors.New("unexpected redispatch after terminal response")
	}
	return d.payload, nil
}

func TestCompactionTerminalRound3HomeReleasesCanceledAttemptOnce(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			m, e, hook, _, model := terminalRound3Manager(t)
			m.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}})
			dispatch := &terminalRound3HomeDispatcher{payload: []byte(fmt.Sprintf(`{"concurrency":{"accounted":true,"credential_id":"home-A","model":%q},"auth_index":"home-A","auth":{"id":"home-A","provider":"codex"}}`, model))}
			reg := executionregistry.New()
			m.PublishHomeDispatch(dispatch, reg, 1)
			releases := 0
			var attempt context.Context
			reg.SetReleaseSink(func(group executionregistry.ReleaseGroup, seq int64) {
				releases++
				if group.CredentialID != "home-A" || group.Model != model || seq != 1 {
					t.Errorf("release = %+v sequence=%d", group, seq)
				}
				if attempt == nil || attempt.Err() != context.Canceled {
					t.Error("Home scope released before attempt cancellation")
				}
			})
			calls := 0
			opts := core.Options{Stream: true, SourceFormat: translator.FormatOpenAIResponse, OriginalRequest: []byte(`{"input":[]}`)}
			opts.RequestAfterAuthInterceptor = func(ctx context.Context, _ core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
				calls++
				attempt = ctx
				return core.RequestAfterAuthInterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: http.Header{"X-Terminal": {"home"}}, ResponseBody: []byte("home terminal")}
			}
			ctx := context.Background()
			err := terminalRound3Run(ctx, m, "stream", model, opts)
			var direct *core.RequestTerminatedError
			if !errors.As(err, &direct) || direct.StatusCode() != status || string(direct.ResponseBody()) != "home terminal" || direct.ResponseHeaders().Get("X-Terminal") != "home" {
				t.Errorf("Home response = %v", err)
			}
			if calls != 1 || dispatch.calls != 1 || len(e.calls) != 0 || hook.results != 0 || releases != 1 {
				t.Errorf("hooks=%d dispatch=%d executor=%v results=%d releases=%d", calls, dispatch.calls, e.calls, hook.results, releases)
			}
			if attempt == nil || attempt.Err() != context.Canceled || ctx.Err() != nil {
				t.Error("attempt must be canceled while parent remains live")
			}
			if frozen := reg.FreezeInFlight(time.Now()); len(frozen.Executions) != 0 {
				t.Errorf("leaked Home execution: %+v", frozen)
			}
			if releases != 1 {
				t.Errorf("release repeated during freeze: %d", releases)
			}
		})
	}
}
