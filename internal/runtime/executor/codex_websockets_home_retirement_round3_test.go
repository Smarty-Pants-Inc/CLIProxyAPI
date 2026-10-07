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
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Real cached sockets and the public Home dispatcher/registry: retirement ends
// the selected Home lifecycle synchronously, but must not swallow its local stop.
func TestCodexCachedWebsocketHomeRetirementRound3(t *testing.T) {
	for _, mode := range []string{"open-json-refusal", "terminal-budget-refusal", "completed-reuse"} {
		t.Run(mode, func(t *testing.T) {
			var connections, creates atomic.Int32
			firstClosed := make(chan struct{})
			releaseFirst := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				n := connections.Add(1)
				defer c.Close()
				if n == 1 {
					defer close(firstClosed)
				}
				_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
				write := func(s string) bool { return c.WriteMessage(websocket.TextMessage, []byte(s)) == nil }
				for {
					if _, _, err := c.ReadMessage(); err != nil {
						return
					}
					turn := creates.Add(1)
					id := fmt.Sprintf("home-fresh-%d", turn)
					if n == 1 && turn > 1 && mode != "completed-reuse" {
						id = "OLD_ABANDONED_RESPONSE"
					}
					if !write(fmt.Sprintf(`{"type":"response.created","response":{"id":%q,"model":"model-a","output":[]}}`, id)) {
						return
					}
					if turn == 1 {
						if !write(`{"type":"response.output_text.delta","response_id":"home-fresh-1","delta":"bootstrap"}`) {
							return
						}
						select {
						case <-releaseFirst:
						case <-r.Context().Done():
							return
						}
						if mode == "open-json-refusal" {
							if !write(`{"type":"response.output_item.done","response_id":"home-fresh-1","output_index":0,"item":{"type":"compaction","encrypted_content":"a","encrypted_content":"b"}}`) {
								return
							}
							continue // Deliberately keep the refused upstream response open.
						}
					}
					output := ""
					if turn == 1 && mode == "terminal-budget-refusal" {
						items := make([]string, 257)
						for i := range items {
							items[i] = fmt.Sprintf(`{"type":"compaction","encrypted_content":"home-%d"}`, i)
						}
						output = strings.Join(items, ",")
					}
					if !write(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"model":"model-a","output":[%s]}}`, id, output)) {
						return
					}
				}
			}))
			defer server.Close()
			origin := auth.NewSessionAffinitySelector(nil)
			defer origin.Stop()
			hook := &retirementResultHook{}
			manager := auth.NewManager(nil, origin, hook)
			manager.SetConfig(&config.Config{})
			exec := NewCodexWebsocketsExecutor(&config.Config{})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			manager.RegisterExecutor(exec)
			defer manager.CloseExecutionSession(t.Name())
			parent, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			ctx := core.WithDownstreamWebsocket(parent) // no duplex input
			payload := []byte(`{"model":"model-a","input":[]}`)
			// Capture positive authority through the public API BEFORE Home enable.
			opts, err := manager.PrepareCompactionRequest("model-a", core.Options{SourceFormat: translator.FormatCodex, OriginalRequest: payload, Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := &accountedWebsocketHomeDispatcher{provider: "codex", baseURL: server.URL}
			homeRegistry := executionregistry.New()
			releases := make(chan executionregistry.ReleaseGroup, 4)
			homeRegistry.SetReleaseSink(func(group executionregistry.ReleaseGroup, _ int64) { dispatcher.releases.Add(1); releases <- group })
			manager.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}})
			manager.PublishHomeDispatch(dispatcher, homeRegistry, 1)
			var selection *auth.HomeDispatchSelection
			run := func(first bool) (string, error) {
				stream, err := manager.ExecuteStream(ctx, []string{"codex"}, core.Request{Model: "model-a", Payload: payload}, opts)
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
						if first && mode != "completed-reuse" && (selection == nil || selection.Active() || dispatcher.releases.Load() != 1) {
							t.Fatalf("typed stop preceded Home retirement: selection=%v releases=%d", selection, dispatcher.releases.Load())
						}
					}
					if first && !released && strings.Contains(string(chunk.Payload), "response.output_text.delta") {
						sess := exec.getOrCreateSession(t.Name())
						sess.connMu.Lock()
						selection, _ = sess.lifecycle.(*auth.HomeDispatchSelection)
						sess.connMu.Unlock()
						if selection == nil || !selection.Active() || !selection.Retained() {
							t.Fatal("actual Home lifecycle not bound/retained before refusal")
						}
						released = true
						close(releaseFirst)
					}
				}
				return wire.String(), terminal
			}
			first, err := run(true)
			if selection == nil {
				t.Fatal("response never reached actual Home lifecycle")
			}
			if mode != "completed-reuse" {
				if !auth.IsLocalCompactionAffinityStop(err) || parent.Err() != nil || strings.Contains(first, "response.completed") {
					t.Fatalf("Home swallowed local stop: err=%v parent=%v wire=%s", err, parent.Err(), first)
				}
				if selection.Active() || hook.results.Load() != 0 {
					t.Fatalf("retirement/accounting: active=%v results=%d", selection.Active(), hook.results.Load())
				}
				select {
				case <-firstClosed:
				case <-parent.Done():
					t.Fatal("exact refused socket remained open")
				}
				select {
				case group := <-releases:
					if group.CredentialID != "accounted-websocket-auth" || group.Model != "model-a" {
						t.Fatalf("wrong Home release: %+v", group)
					}
				case <-parent.Done():
					t.Fatal("Home scope not released")
				}
				if dispatcher.releases.Load() != 1 {
					t.Fatalf("Home releases=%d want 1", dispatcher.releases.Load())
				}
				if current, ok := manager.GetByID("accounted-websocket-auth"); ok && (current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || len(current.ModelStates) != 0) {
					t.Fatalf("local refusal mutated cooldown: %+v", current)
				}
			} else if err != nil || !strings.Contains(first, "response.completed") || !selection.Active() || dispatcher.releases.Load() != 0 {
				t.Fatalf("completed Home reuse lost: err=%v active=%v releases=%d", err, selection.Active(), dispatcher.releases.Load())
			}
			second, err := run(false)
			if err != nil || !strings.Contains(second, "home-fresh-2") || strings.Contains(second, "OLD_ABANDONED_RESPONSE") {
				t.Fatalf("next Home response: err=%v wire=%s", err, second)
			}
			want := int32(2)
			if mode == "completed-reuse" {
				want = 1
			}
			if connections.Load() != want || dispatcher.calls.Load() != want || creates.Load() != 2 {
				t.Fatalf("connections=%d dispatches=%d creates=%d want=%d", connections.Load(), dispatcher.calls.Load(), creates.Load(), want)
			}
			if mode != "completed-reuse" && !dispatcher.before.Load() {
				t.Fatal("redispatch preceded Home release")
			}
		})
	}
}

// Synchronous Home release can cancel ROOT during Complete(false). A local
// terminal must not revive it, even with an output receiver ready.
func TestCodexCachedWebsocketHomeRetirementRound3CanceledRoot(t *testing.T) {
	release := make(chan struct{})
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer close(closed)
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		for _, s := range []string{`{"type":"response.created","response":{"id":"root-cancel","model":"model-a","output":[]}}`, `{"type":"response.output_text.delta","response_id":"root-cancel","delta":"bootstrap"}`} {
			if c.WriteMessage(websocket.TextMessage, []byte(s)) != nil {
				return
			}
		}
		<-release
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.output_item.done","response_id":"root-cancel","output_index":0,"item":{"type":"compaction","encrypted_content":"a","encrypted_content":"b"}}`))
		_, _, _ = c.ReadMessage()
	}))
	defer server.Close()
	origin := auth.NewSessionAffinitySelector(nil)
	defer origin.Stop()
	hook := &retirementResultHook{}
	manager := auth.NewManager(nil, origin, hook)
	manager.SetConfig(&config.Config{})
	exec := NewCodexWebsocketsExecutor(&config.Config{})
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	manager.RegisterExecutor(exec)
	defer manager.CloseExecutionSession(t.Name())
	parent, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ctx := core.WithDownstreamWebsocket(parent)
	payload := []byte(`{"model":"model-a","input":[]}`)
	opts, err := manager.PrepareCompactionRequest("model-a", core.Options{SourceFormat: translator.FormatCodex, OriginalRequest: payload, Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &accountedWebsocketHomeDispatcher{provider: "codex", baseURL: server.URL}
	homeRegistry := executionregistry.New()
	released := make(chan struct{}, 2)
	homeRegistry.SetReleaseSink(func(executionregistry.ReleaseGroup, int64) {
		dispatcher.releases.Add(1)
		cancel()
		released <- struct{}{}
	})
	manager.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}})
	manager.PublishHomeDispatch(dispatcher, homeRegistry, 1)
	stream, err := manager.ExecuteStream(ctx, []string{"codex"}, core.Request{Model: "model-a", Payload: payload}, opts)
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	var selection *auth.HomeDispatchSelection
	canceled := false
	for chunk := range stream.Chunks {
		if canceled {
			t.Fatalf("delivered after root cancellation: payload=%s err=%v", chunk.Payload, chunk.Err)
		}
		if strings.Contains(string(chunk.Payload), "response.output_text.delta") {
			sess := exec.getOrCreateSession(t.Name())
			sess.connMu.Lock()
			selection, _ = sess.lifecycle.(*auth.HomeDispatchSelection)
			sess.connMu.Unlock()
			// Parent remains live until local retirement invokes the release sink.
			if parent.Err() != nil {
				t.Fatal("root canceled before local refusal")
			}
			canceled = true
			close(release)
		}
	}
	if !canceled {
		close(release)
		t.Fatal("root-cancel fixture never reached bootstrap")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled Home socket remained open")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("canceled Home scope not released")
	}
	if parent.Err() == nil || selection == nil || selection.Active() || dispatcher.releases.Load() != 1 || hook.results.Load() != 0 {
		t.Fatalf("root cancellation ownership: selection=%v releases=%d results=%d", selection, dispatcher.releases.Load(), hook.results.Load())
	}
}
