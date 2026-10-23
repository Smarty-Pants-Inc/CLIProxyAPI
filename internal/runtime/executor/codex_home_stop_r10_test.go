package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type r10HomeDispatcher struct {
	auths []*auth.Auth
	calls atomic.Int32
}

func (*r10HomeDispatcher) HeartbeatOK() bool       { return true }
func (*r10HomeDispatcher) AbortAmbiguousDispatch() {}
func (d *r10HomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	i := int(d.calls.Add(1)) - 1
	if i >= len(d.auths) {
		return nil, fmt.Errorf("unexpected dispatch %d", i+1)
	}
	return json.Marshal(d.auths[i])
}

type r10ResultHook struct {
	auth.NoopHook
	mu       sync.Mutex
	recorded []auth.Result
}

func (h *r10ResultHook) OnResult(_ context.Context, result auth.Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recorded = append(h.recorded, result)
}
func (h *r10ResultHook) results() []auth.Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]auth.Result(nil), h.recorded...)
}

func newR10HomeFixture(t *testing.T, frames []string, beforeCut int) (*WSReplayFixture, *r10HomeDispatcher, *r10ResultHook, core.WebSocketResponseObserver) {
	t.Helper()
	fixture := &WSReplayFixture{primaryID: t.Name() + "-a"}
	consumed := make(chan struct{})
	var once sync.Once
	openGate := func() { once.Do(func() { close(consumed) }) }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil {
			t.Error(err)
			return
		}
		if r.Header.Get("Authorization") == "Bearer fixture-secondary" {
			fixture.secondaryRequests.Add(1)
			_ = conn.WriteMessage(websocket.TextMessage, []byte(WSReplayCompleted))
			// Keep a successful cached connection alive until its owner closes it.
			_, _, _ = conn.ReadMessage()
			return
		}
		fixture.primaryRequests.Add(1)
		for i, frame := range frames {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
				return
			}
			if i+1 == beforeCut {
				<-consumed
			}
		}
	}))
	t.Cleanup(server.Close)
	cfg := &config.Config{Home: config.HomeConfig{Enabled: true}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	t.Cleanup(func() { exec.CloseExecutionSession(auth.CloseAllExecutionSessionsID) })
	t.Cleanup(openGate)
	hook := &r10ResultHook{}
	fixture.manager = auth.NewManager(nil, nil, hook)
	fixture.manager.SetConfig(cfg)
	fixture.manager.SetRetryConfig(0, 0, 2)
	fixture.manager.RegisterExecutor(exec)
	dispatcher := &r10HomeDispatcher{}
	for i, token := range []string{"fixture-primary", "fixture-secondary"} {
		id := fixture.primaryID
		if i == 1 {
			id = t.Name() + "-b"
		}
		dispatcher.auths = append(dispatcher.auths, &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": token, "base_url": server.URL, "websockets": "true"}})
	}
	fixture.manager.PublishHomeDispatch(dispatcher, executionregistry.New(), 1)
	var observed atomic.Int32
	observer := func(_ context.Context, event core.WebSocketResponseEvent) {
		if event.AuthID == fixture.primaryID && int(observed.Add(1)) == beforeCut {
			openGate()
		}
	}
	return fixture, dispatcher, hook, observer
}

// Recorded catch: PR #174 R9-1 and N-9. Real Home dispatch -> conductor ->
// Codex WS transport. Unsafe server effects must not replay, and their terminal
// error must reach the caller even when retiring the socket ends the Home scope.
func TestCodexHomeStopR10(t *testing.T) {
	shapes := []struct {
		name   string
		frames []string
		work   bool
	}{
		{"web_search", []string{WSReplayUnsafeTool}, true},
		{"function_then_mcp", []string{
			`{"type":"response.output_item.added","item":{"type":"function_call","id":"fc","name":"lookup","arguments":"{}"}}`,
			`{"type":"response.output_item.added","item":{"type":"mcp_call","id":"mcp","status":"in_progress"}}`}, true},
		{"image_generation", []string{`{"type":"response.output_item.added","item":{"type":"image_generation_call","id":"img","status":"in_progress"}}`}, true},
		{"snapshot_mcp", []string{`{"type":"response.in_progress","response":{"id":"resp_replay","model":"gpt-5.6-terra","output":[{"type":"mcp_call","id":"mcp","status":"in_progress"}]}}`}, true},
		{"local_shell", []string{`{"type":"response.output_item.added","item":{"type":"local_shell_call","id":"shell"}}`}, true},
		{"future_item", []string{`{"type":"response.output_item.added","item":{"type":"future_tool_call","id":"future"}}`}, true},
		{"text", []string{`{"type":"response.output_text.delta","delta":"hello"}`}, false},
		{"reasoning", []string{`{"type":"response.reasoning_summary_text.delta","delta":"thinking"}`}, false},
		{"function_call", []string{`{"type":"response.output_item.added","item":{"type":"function_call","id":"fc","name":"lookup","arguments":"{}"}}`}, false},
	}
	for _, format := range []translator.Format{translator.FormatGemini, translator.FormatOpenAIResponse} {
		for _, stream := range []bool{false, true} {
			for _, shape := range shapes {
				for _, cut := range []string{"failed", "wserr429", "usage_limit", "drop"} {
					t.Run(fmt.Sprintf("format=%s/stream=%t/%s/%s", format, stream, shape.name, cut), func(t *testing.T) {
						frames := append([]string{WSReplayIdentity}, shape.frames...)
						if format == translator.FormatOpenAIResponse {
							frames = append([]string{WSReplayPreamble}, frames...)
						}
						beforeCut := len(frames)
						switch cut {
						case "failed":
							frames = append(frames, `{"type":"response.failed","response":{"id":"resp_replay","model":"gpt-5.6-terra","error":{"type":"server_error","message":"failed"}}}`)
						case "wserr429":
							frames = append(frames, `{"type":"error","status":429,"error":{"type":"rate_limit_exceeded","message":"limited"}}`)
						case "usage_limit":
							frames = append(frames, `{"type":"response.failed","response":{"id":"resp_replay","model":"gpt-5.6-terra","error":{"type":"usage_limit_reached","resets_in_seconds":60}}}`)
						}
						fixture, dispatcher, hook, observer := newR10HomeFixture(t, frames, beforeCut)
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						opts := core.Options{SourceFormat: translator.FormatCodex, ResponseFormat: format, Stream: stream, WebSocketResponseObserver: observer}
						if stream {
							opts.Metadata = map[string]any{core.ExecutionSessionMetadataKey: t.Name()}
						}
						req := core.Request{Model: WSReplayModel, Payload: []byte(`{"model":"gpt-5.6-terra","input":[]}`)}
						var payload string
						var err error
						if stream {
							var result *core.StreamResult
							result, err = fixture.manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
							if result != nil {
								var tail error
								payload, tail = drainChunks(result)
								if err == nil {
									err = tail
								}
							}
						} else {
							var result core.Response
							result, err = fixture.manager.Execute(ctx, []string{"codex"}, req, opts)
							payload = string(result.Payload)
						}
						first, second := fixture.primaryRequests.Load(), fixture.secondaryRequests.Load()
						t.Logf("R10 format=%s stream=%t shape=%s cut=%s work=%t A=%d B=%d dispatch=%d error=%v body=%q", format, stream, shape.name, cut, shape.work, first, second, dispatcher.calls.Load(), err, payload)
						// Text/reasoning are visible in streams; the non-stream cases prove safe failover.
						if !shape.work {
							if !stream && (err != nil || second != 1 || payload == "") {
								t.Errorf("model-only Home failover failed: %v %s", err, payload)
							}
							return
						}
						if first != 1 || second != 0 || dispatcher.calls.Load() != 1 {
							t.Errorf("unsafe work replayed: A=%d B=%d dispatch=%d", first, second, dispatcher.calls.Load())
						}
						if err == nil {
							t.Fatal("server work stop lost terminal error")
						}
						if cut != "drop" {
							results := hook.results()
							wantStatus := 429
							if cut == "failed" {
								wantStatus = http.StatusBadGateway
							}
							if len(results) != 1 || results[0].AuthID != fixture.primaryID || results[0].Success || results[0].Error == nil || results[0].Error.StatusCode() != wantStatus {
								t.Errorf("Home cooling report lost: %+v", results)
							}
						}
						if !stream && payload != "" {
							t.Errorf("unsafe non-stream returned body: %s", payload)
						}
						if cut == "drop" && stream {
							var scoped interface{ IsRequestScoped() bool }
							if !errors.As(err, &scoped) || !scoped.IsRequestScoped() || !strings.Contains(err.Error(), "upstream_stream_incomplete") {
								t.Errorf("want request-scoped upstream_stream_incomplete, got %T %v", err, err)
							}
						}
					})
				}
			}
		}
	}
}
