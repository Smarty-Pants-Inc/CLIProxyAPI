package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type retirementResultHook struct {
	auth.NoopHook
	results atomic.Int32
}

func (h *retirementResultHook) OnResult(context.Context, auth.Result) { h.results.Add(1) }

// Existing public APIs only: real non-duplex cached Codex sockets, a captured
// affinity origin and Manager.ExecuteStream. The caller stays live on refusal.
func TestCodexCachedWebsocketManagerRetirement(t *testing.T) {
	for _, mode := range []string{"open-json-refusal", "terminal-budget-refusal", "bootstrap-terminal-budget-refusal", "completed-reuse"} {
		t.Run(mode, func(t *testing.T) {
			const model = "cached-retirement-model"
			var connections, creates atomic.Int32
			firstClosed := make(chan struct{})
			releaseFirst := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				n := connections.Add(1)
				defer func() { _ = c.Close() }()
				if n == 1 {
					defer close(firstClosed)
				}
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				write := func(payload string) bool {
					return c.WriteMessage(websocket.TextMessage, []byte(payload)) == nil
				}
				for {
					if _, _, errRead := c.ReadMessage(); errRead != nil {
						return
					}
					turn := creates.Add(1)
					responseID := fmt.Sprintf("fresh-%d", turn)
					if n == 1 && turn > 1 && mode != "completed-reuse" {
						// A reused abandoned socket still belongs to the old response.
						responseID = "OLD_ABANDONED_RESPONSE"
					}
					if !write(fmt.Sprintf(`{"type":"response.created","response":{"id":%q,"model":%q,"output":[]}}`, responseID, model)) {
						return
					}
					if n == 1 && turn == 1 && mode != "bootstrap-terminal-budget-refusal" {
						if !write(`{"type":"response.output_text.delta","response_id":"fresh-1","delta":"bootstrap"}`) {
							return
						}
						select {
						case <-releaseFirst:
						case <-r.Context().Done():
							return
						}
					}
					if n == 1 && turn == 1 && mode == "open-json-refusal" {
						if !write(`{"type":"response.output_item.done","response_id":"fresh-1","output_index":0,"item":{"type":"compaction","encrypted_content":"a","encrypted_content":"b"}}`) {
							return
						}
						// Deliberately leave the upstream response open.
						continue
					}
					output := ""
					if n == 1 && turn == 1 && strings.Contains(mode, "budget-refusal") {
						items := make([]string, 257)
						for i := range items {
							items[i] = fmt.Sprintf(`{"type":"compaction","encrypted_content":"retirement-%d"}`, i)
						}
						output = strings.Join(items, ",")
					}
					if !write(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"model":%q,"output":[%s]}}`, responseID, model, output)) {
						return
					}
				}
			}))
			defer upstream.Close()
			cfg := &config.Config{}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			origin := auth.NewSessionAffinitySelector(nil)
			defer origin.Stop()
			hook := &retirementResultHook{}
			manager := auth.NewManager(nil, origin, hook)
			manager.SetConfig(cfg)
			manager.RegisterExecutor(exec)
			id := t.Name()
			candidate := &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "test-key", "base_url": upstream.URL, "websockets": "true"}}
			if _, err := manager.Register(context.Background(), candidate); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
			defer registry.GetGlobalRegistry().UnregisterClient(id)
			parent, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			ctx := core.WithDownstreamWebsocket(parent) // no input: ordinary non-duplex path
			payload := []byte(fmt.Sprintf(`{"model":%q,"input":[]}`, model))
			run := func(first bool) (string, error) {
				stream, err := manager.ExecuteStream(ctx, []string{"codex"}, core.Request{Model: model, Payload: payload}, core.Options{SourceFormat: translator.FormatCodex, OriginalRequest: payload, Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}})
				if err != nil {
					return "", err
				}
				var wire strings.Builder
				var terminal error
				released := false
				for chunk := range stream.Chunks {
					wire.Write(chunk.Payload)
					if chunk.Err != nil {
						terminal = chunk.Err
					}
					if first && !released && strings.Contains(string(chunk.Payload), "response.output_text.delta") {
						released = true
						close(releaseFirst)
					}
				}
				return wire.String(), terminal
			}
			first, err := run(true)
			if mode != "completed-reuse" {
				if !auth.IsLocalCompactionAffinityStop(err) || parent.Err() != nil || strings.Contains(first, "response.completed") {
					t.Fatalf("local refusal lost: err=%v parent=%v wire=%s", err, parent.Err(), first)
				}
				if hook.results.Load() != 0 {
					t.Fatalf("local refusal published %d results", hook.results.Load())
				}
				current, _ := manager.GetByID(id)
				if current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || len(current.ModelStates) != 0 {
					t.Fatalf("local refusal changed availability: %+v", current)
				}
				select {
				case <-firstClosed:
				case <-time.After(time.Second):
					t.Fatal("refused cached upstream connection remained open")
				}
			} else if err != nil || !strings.Contains(first, "response.completed") {
				t.Fatalf("ordinary completion: %v %s", err, first)
			}
			second, err := run(false)
			if err != nil || !strings.Contains(second, "fresh-2") || strings.Contains(second, "OLD_ABANDONED_RESPONSE") {
				t.Fatalf("next response received abandoned bytes: err=%v wire=%s", err, second)
			}
			wantConnections := int32(2)
			if mode == "completed-reuse" {
				wantConnections = 1
			}
			if connections.Load() != wantConnections || creates.Load() != 2 {
				t.Fatalf("connections=%d want=%d creates=%d", connections.Load(), wantConnections, creates.Load())
			}
		})
	}
}

// A terminal channel close is not itself permission to reuse. This direct
// consumer opts into the same typed contract used by the public Manager above.
func TestCodexCachedWebsocketValidationOwnsReuse(t *testing.T) {
	for _, mode := range []string{"cancel-unacknowledged", "reject", "accept"} {
		t.Run(mode, func(t *testing.T) {
			accept := mode == "accept"
			const model = "validation-retirement-model"
			var connections, creates atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				connections.Add(1)
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
				for {
					if _, _, err := c.ReadMessage(); err != nil {
						return
					}
					n := creates.Add(1)
					for _, kind := range []string{"response.created", "response.completed"} {
						payload := fmt.Sprintf(`{"type":%q,"response":{"id":"validation-%d","model":%q,"output":[]}}`, kind, n, model)
						if c.WriteMessage(websocket.TextMessage, []byte(payload)) != nil {
							return
						}
					}
				}
			}))
			defer upstream.Close()
			exec := NewCodexWebsocketsExecutor(&config.Config{})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(t.Name())
			candidate := &auth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"api_key": "test-key", "base_url": upstream.URL}}
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			firstCtx, cancelFirst := context.WithCancel(core.WithDownstreamWebsocket(ctx))
			defer cancelFirst()
			payload := []byte(fmt.Sprintf(`{"model":%q,"input":[]}`, model))
			req := core.Request{Model: model, Payload: payload}
			opts := core.Options{SourceFormat: translator.FormatCodex, OriginalRequest: payload, StreamResultValidation: true, Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}}
			first, err := exec.ExecuteStream(firstCtx, candidate, req, opts)
			if err != nil {
				t.Fatal(err)
			}
			for chunk := range first.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
			}
			if first.Complete == nil {
				t.Fatal("consumer-validation callback absent")
			}
			sess := exec.getOrCreateSession(t.Name())
			if sess.reqMu.TryLock() {
				sess.reqMu.Unlock()
				t.Fatal("terminal EOF unlocked cached reuse before consumer acknowledgement")
			}
			type outcome struct {
				stream *core.StreamResult
				err    error
			}
			competing := make(chan outcome, 1)
			started := make(chan struct{})
			opts.StreamResultValidation = false // ordinary direct consumer control
			go func() {
				close(started)
				stream, err := exec.ExecuteStream(core.WithDownstreamWebsocket(ctx), candidate, req, opts)
				competing <- outcome{stream: stream, err: err}
			}()
			<-started
			if creates.Load() != 1 {
				t.Fatal("competing request reached upstream while validation was held")
			}
			if mode != "cancel-unacknowledged" {
				first.Complete(accept)
			}
			// Without an acknowledgement, cancellation retires the first conn.
			// With an acknowledgement, normal child cancellation preserves it.
			cancelFirst()
			var second outcome
			select {
			case second = <-competing:
			case <-ctx.Done():
				t.Fatal("competing request was not released by final disposition")
			}
			if second.err != nil {
				t.Fatal(second.err)
			}
			for chunk := range second.stream.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
			}
			// The canceled first consumer's previously unused callback arrives
			// after the replacement is installed. It must not kill that socket.
			first.Complete(false)
			third, err := exec.ExecuteStream(core.WithDownstreamWebsocket(ctx), candidate, req, opts)
			if err != nil {
				t.Fatal(err)
			}
			for chunk := range third.Chunks {
				if chunk.Err != nil {
					t.Fatal(chunk.Err)
				}
			}
			want := int32(2)
			if accept {
				want = 1
			}
			if connections.Load() != want || creates.Load() != 3 {
				t.Fatalf("delayed disposition retired replacement: connections=%d want=%d creates=%d", connections.Load(), want, creates.Load())
			}
			select {
			case err := <-exec.UpstreamDisconnectChan(t.Name()):
				t.Fatalf("local retirement notified downstream disconnect: %v", err)
			default:
			}
		})
	}
}
