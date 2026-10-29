package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

type protectedCooldownCall struct {
	authID, pin       string
	payload, original []byte
}

// Keep reason: credential/data trust boundary. Inspect both executor bodies,
// not just seat selection: signed context must never reach a different account.
func TestManagerClaudeProtectedSessionDegradesBeforeCooldownFailover(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, path := range []string{"execute", "stream"} {
		for _, scenario := range []string{"quota-summary", "unavailable-summary", "ineligible-summary", "missing-openai-summary", "quota-encrypted", "quota-no-block"} {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				manager, selector, calls := newProtectedCooldownManager(t)
				a, b, c := t.Name()+"-A", t.Name()+"-B", t.Name()+"-C"
				registerConductorSessionAffinityCooldownAuth(t, manager, a, conductorSessionAffinityCooldownModel, 0, false)
				req, opts := nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", true)
				if err := runProtectedCooldownRequest(t, manager, path, req, opts); err != nil {
					t.Fatal(err)
				}
				opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
				opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = req.Model
				block := nativeClaudeBlock
				if scenario == "quota-encrypted" {
					block = `{"type":"compaction","encrypted_content":"signed-account-a"}`
					if err := selector.RecordCompactionOutput(a, opts, []byte(`{"content":[`+block+`]}`)); err != nil {
						t.Fatal(err)
					}
				} else if err := selector.RecordCompactionOutput(a, opts, []byte(`{"content":[`+block+`]}`)); err != nil {
					t.Fatal(err)
				}
				primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
				primary := "mixed::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + req.Model
				assertProtectedCooldownBinding(t, selector, primary, a, true)
				signedReq, signedOpts := nativeClaudeRequest(req.Model, block, true)
				keys := compactionAffinityKeys(signedOpts)
				if len(keys) != 1 {
					t.Fatalf("fixture signer keys = %v", keys)
				}
				assertProtectedCooldownBinding(t, selector, keys[0], a, true)
				registerConductorSessionAffinityCooldownAuth(t, manager, b, req.Model, 0, false)
				registerConductorSessionAffinityCooldownAuth(t, manager, c, req.Model, 0, false)
				switch scenario {
				case "missing-openai-summary":
					manager.Remove(context.Background(), a)
					signedOpts.SourceFormat = sdktranslator.FormatOpenAIResponse
				case "unavailable-summary":
					seat, _ := manager.GetByID(a)
					seat.Unavailable = true
					seat.Status = StatusError
					seat.LastError = &Error{HTTPStatus: http.StatusUnauthorized, Code: "unauthorized"}
					if _, err := manager.Update(context.Background(), seat); err != nil {
						t.Fatal(err)
					}
				case "ineligible-summary":
					registry.GetGlobalRegistry().RegisterClient(a, "claude", []*registry.ModelInfo{{ID: req.Model + "-other"}})
				default:
					markConductorSessionAffinityCooldown(t, manager, a, req.Model, http.StatusTooManyRequests)
				}
				if scenario == "quota-no-block" {
					signedReq, signedOpts = nativeClaudeRequest(req.Model, "", true)
				}
				*calls = nil
				if err := runProtectedCooldownRequest(t, manager, path, signedReq, signedOpts); err != nil {
					t.Fatalf("protected session must degrade/reselect before execution: %v", err)
				}
				if len(*calls) != 1 || ((*calls)[0].authID != b && (*calls)[0].authID != c) {
					t.Fatalf("calls = %+v, want exactly one healthy seat", *calls)
				}
				call := (*calls)[0]
				if call.pin != "" {
					t.Errorf("degraded executor retained hard pin %q", call.pin)
				}
				for _, body := range [][]byte{call.payload, call.original} {
					if !gjson.ValidBytes(body) || bytes.Contains(body, []byte(`"compaction"`)) || bytes.Contains(body, []byte("signed-account-a")) {
						t.Errorf("wrong-seat signed block leaked in executor body: %s", body)
					}
					if strings.HasSuffix(scenario, "summary") && gjson.GetBytes(body, "messages.0.content.0.type").String() != "text" {
						t.Errorf("summary not converted to native text: %s", body)
					}
					if strings.HasSuffix(scenario, "summary") && gjson.GetBytes(body, "messages.0.content.0.text").String() != "native-signed-summary" {
						t.Errorf("plain summary was lost: %s", body)
					}
					if scenario == "quota-no-block" && !bytes.Equal(body, signedReq.Payload) {
						t.Errorf("no-block request changed: %s", body)
					}
				}
				assertProtectedCooldownBinding(t, selector, primary, call.authID, false)
				assertProtectedCooldownBinding(t, selector, keys[0], a, true)

				// A new identity-free replay must still find the original signer,
				// not the mutable conversation's newly selected seat.
				if scenario == "missing-openai-summary" {
					registerConductorSessionAffinityCooldownAuth(t, manager, a, req.Model, 0, false)
				}
				registry.GetGlobalRegistry().RegisterClient(a, "claude", []*registry.ModelInfo{{ID: req.Model}})
				manager.MarkResult(context.Background(), Result{AuthID: a, Provider: "claude", Model: req.Model, Success: true})
				if scenario == "unavailable-summary" {
					seat, _ := manager.GetByID(a)
					seat.Unavailable = false
					seat.Status = StatusActive
					seat.LastError = nil
					if _, err := manager.Update(context.Background(), seat); err != nil {
						t.Fatal(err)
					}
				}
				replayReq, replayOpts := nativeClaudeRequest(req.Model, block, false)
				*calls = nil
				if err := runProtectedCooldownRequest(t, manager, path, replayReq, replayOpts); err != nil {
					t.Fatalf("recovered original signer replay: %v", err)
				}
				assertProtectedCooldownPinned(t, *calls, a, replayReq.Payload, replayOpts.OriginalRequest)
				assertProtectedCooldownBinding(t, selector, primary, call.authID, false)
			})
		}
	}
}

func TestManagerClaudeProtectedHealthySignerKeepsSignedBody(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			manager, selector, calls := newProtectedCooldownManager(t)
			a, b := t.Name()+"-A", t.Name()+"-B"
			registerConductorSessionAffinityCooldownAuth(t, manager, a, conductorSessionAffinityCooldownModel, 0, false)
			req, opts := nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", true)
			if err := runProtectedCooldownRequest(t, manager, path, req, opts); err != nil {
				t.Fatal(err)
			}
			opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
			opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = req.Model
			if err := selector.RecordCompactionOutput(a, opts, []byte(`{"content":[`+nativeClaudeBlock+`]}`)); err != nil {
				t.Fatal(err)
			}
			registerConductorSessionAffinityCooldownAuth(t, manager, b, req.Model, 10, false)
			req, opts = nativeClaudeRequest(req.Model, nativeClaudeBlock, true)
			*calls = nil
			if err := runProtectedCooldownRequest(t, manager, path, req, opts); err != nil {
				t.Fatal(err)
			}
			assertProtectedCooldownPinned(t, *calls, a, req.Payload, opts.OriginalRequest)
			primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
			primary := "mixed::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + req.Model
			assertProtectedCooldownBinding(t, selector, primary, a, true)
		})
	}
}

func TestManagerClaudeProtectedAllSeatsCoolingReturnsModelCooldown(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			manager, selector, calls := newProtectedCooldownManager(t)
			a, b := t.Name()+"-A", t.Name()+"-B"
			registerConductorSessionAffinityCooldownAuth(t, manager, a, conductorSessionAffinityCooldownModel, 0, false)
			req, opts := nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", true)
			opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
			opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = req.Model
			if err := selector.RecordCompactionOutput(a, opts, []byte(`{"content":[`+nativeClaudeBlock+`]}`)); err != nil {
				t.Fatal(err)
			}
			registerConductorSessionAffinityCooldownAuth(t, manager, b, req.Model, 0, false)
			markConductorSessionAffinityCooldown(t, manager, a, req.Model, http.StatusTooManyRequests)
			markConductorSessionAffinityCooldown(t, manager, b, req.Model, http.StatusTooManyRequests)
			req, opts = nativeClaudeRequest(req.Model, nativeClaudeBlock, true)
			err := runProtectedCooldownRequest(t, manager, path, req, opts)
			var cooldown *modelCooldownError
			if !errors.As(err, &cooldown) || statusCodeFromError(err) != http.StatusTooManyRequests {
				t.Fatalf("all cooling = %v, want model cooldown 429", err)
			}
			if len(*calls) != 0 {
				t.Fatalf("all-cooling upstream calls = %+v", *calls)
			}
		})
	}
}

func TestManagerClaudeOrdinaryExplicitPinReleasesCoolingSeat(t *testing.T) {
	withQuotaCooldownEnabled(t)
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			manager, _, calls := newProtectedCooldownManager(t)
			a, b := t.Name()+"-A", t.Name()+"-B"
			registerConductorSessionAffinityCooldownAuth(t, manager, a, conductorSessionAffinityCooldownModel, 0, false)
			registerConductorSessionAffinityCooldownAuth(t, manager, b, conductorSessionAffinityCooldownModel, 0, false)
			req, opts := nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", true)
			opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = a
			if err := runProtectedCooldownRequest(t, manager, path, req, opts); err != nil {
				t.Fatalf("healthy explicit pin: %v", err)
			}
			assertProtectedCooldownPinned(t, *calls, a, req.Payload, opts.OriginalRequest)
			markConductorSessionAffinityCooldown(t, manager, a, conductorSessionAffinityCooldownModel, http.StatusTooManyRequests)
			*calls = nil
			req, opts = nativeClaudeRequest(conductorSessionAffinityCooldownModel, "", true)
			opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = a
			if err := runProtectedCooldownRequest(t, manager, path, req, opts); err != nil {
				t.Fatalf("ordinary Claude explicit pin must fail over: %v", err)
			}
			if len(*calls) != 1 || (*calls)[0].authID != b || (*calls)[0].pin != "" {
				t.Fatalf("ordinary explicit-pin calls = %+v, want unpinned B", *calls)
			}
			if !bytes.Equal((*calls)[0].payload, req.Payload) || !bytes.Equal((*calls)[0].original, opts.OriginalRequest) {
				t.Fatal("ordinary explicit-pin request body changed")
			}
		})
	}
}

func newProtectedCooldownManager(t *testing.T) (*Manager, *SessionAffinitySelector, *[]protectedCooldownCall) {
	t.Helper()
	manager, selector, _ := newConductorSessionAffinityCooldownManager(t)
	calls := []protectedCooldownCall{}
	capture := func(auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) {
		calls = append(calls, protectedCooldownCall{authID: auth.ID, pin: pinnedAuthIDFromMetadata(opts.Metadata), payload: bytes.Clone(req.Payload), original: bytes.Clone(opts.OriginalRequest)})
	}
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "claude",
		mockCustomErrorExecutor: mockCustomErrorExecutor{identifier: "claude", executeFn: func(_ context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
			capture(auth, req, opts)
			return cliproxyexecutor.Response{Payload: []byte(`{"content":[{"type":"text","text":"ok"}]}`)}, nil
		}},
		streamFn: func(_ context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			capture(auth, req, opts)
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"ok"}}`)}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
	})
	return manager, selector, &calls
}

func runProtectedCooldownRequest(t *testing.T, manager *Manager, path string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) error {
	t.Helper()
	if path == "execute" {
		_, err := manager.Execute(context.Background(), []string{"claude"}, req, opts)
		return err
	}
	opts.Stream = true
	stream, err := manager.ExecuteStream(context.Background(), []string{"claude"}, req, opts)
	if err != nil {
		return err
	}
	if stream == nil || stream.Chunks == nil {
		t.Fatal("successful ExecuteStream returned no stream")
	}
	var terminal error
	var received bool
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			terminal = chunk.Err
		}
		received = received || len(chunk.Payload) > 0
	}
	if terminal == nil && !received {
		t.Fatal("successful stream contained no payload")
	}
	return terminal
}

func assertProtectedCooldownBinding(t *testing.T, selector *SessionAffinitySelector, key, want string, protected bool) {
	t.Helper()
	got, ok := selector.cache.Get(key)
	if !ok || got != want || selector.cache.IsProtected(key) != protected {
		t.Fatalf("binding %q = (%q, known=%v, protected=%v), want (%q, protected=%v)", key, got, ok, selector.cache.IsProtected(key), want, protected)
	}
}

func assertProtectedCooldownPinned(t *testing.T, calls []protectedCooldownCall, authID string, payload, original []byte) {
	t.Helper()
	if len(calls) != 1 || calls[0].authID != authID || calls[0].pin != authID {
		t.Fatalf("signed replay calls = %+v, want only pinned %q", calls, authID)
	}
	if !bytes.Equal(calls[0].payload, payload) || !bytes.Equal(calls[0].original, original) {
		t.Fatalf("healthy signer body changed: payload=%s original=%s", calls[0].payload, calls[0].original)
	}
}
