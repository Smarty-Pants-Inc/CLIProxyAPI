package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// With stream-bootstrap-buffering off, the pre-output hold still runs: a quota refusal right
// after response.created fails over to the next credential before any byte reaches the client.
// Once the next credential produces its first output frame, the stream is released, and every
// later output frame reaches the client at once (before the upstream sends the next frame).
// The observer sees every frame of the successful attempt, in wire order.
func TestCodexWebsocketsExecutor_BootstrapBufferingOff_RefusalFailsOverThenStreamsAtOnce(t *testing.T) {
	const model = "gpt-5.6-terra"
	created := `{"type":"response.created","response":{"id":"resp_off","model":"gpt-5.6-terra","output":[]}}`
	refusal := `{"type":"response.failed","response":{"id":"resp_off","model":"gpt-5.6-terra","status":"failed","error":` + codexBootstrapQuotaError + `}}`
	delta1 := `{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"first-delta"}`
	delta2 := `{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"second-delta"}`
	completed := `{"type":"response.completed","response":{"id":"resp_off","model":"gpt-5.6-terra","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}`

	serve := func(attempts *atomic.Int32, script func(conn *websocket.Conn)) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err != nil {
				t.Errorf("upgrade websocket: %v", err)
				return
			}
			defer func() { _ = conn.Close() }()
			if _, _, errRead := conn.ReadMessage(); errRead != nil {
				t.Errorf("read websocket request: %v", errRead)
				return
			}
			attempts.Add(1)
			script(conn)
		}))
	}
	write := func(conn *websocket.Conn, frame string) {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
			t.Errorf("write websocket frame: %v", err)
		}
	}

	var refusedAttempts, servedAttempts atomic.Int32
	refusing := serve(&refusedAttempts, func(conn *websocket.Conn) {
		write(conn, created)
		write(conn, refusal)
	})
	defer refusing.Close()
	afterFirst, afterSecond := make(chan struct{}), make(chan struct{})
	var firstOnce, secondOnce sync.Once
	openFirst := func() { firstOnce.Do(func() { close(afterFirst) }) }
	openSecond := func() { secondOnce.Do(func() { close(afterSecond) }) }
	serving := serve(&servedAttempts, func(conn *websocket.Conn) {
		write(conn, created)
		write(conn, delta1)
		<-afterFirst
		write(conn, delta2)
		<-afterSecond
		write(conn, completed)
	})
	defer serving.Close()
	// Registered after Close so they run first: the handler must not block Close.
	defer openSecond()
	defer openFirst()

	cfg := &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: false}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	defer exec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
	manager := cliproxyauth.NewManager(nil, &cliproxyauth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(exec)
	reg := registry.GetGlobalRegistry()
	for _, credential := range []struct{ id, url string }{
		{"a-off-refuses-" + t.Name(), refusing.URL},
		{"b-off-serves-" + t.Name(), serving.URL},
	} {
		auth := &cliproxyauth.Auth{
			ID: credential.id, Provider: "codex", Status: cliproxyauth.StatusActive,
			Attributes: map[string]string{"api_key": "fixture-only", "base_url": credential.url, "websockets": "true"},
			Metadata:   map[string]any{"disable_cooling": false},
		}
		reg.RegisterClient(auth.ID, "codex", []*registry.ModelInfo{{ID: model}})
		id := auth.ID
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	var observed []string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{
		Model: model, Payload: []byte(`{"model":"gpt-5.6-terra","input":[]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"),
		Stream:       true,
		WebSocketResponseObserver: func(_ context.Context, ev cliproxyexecutor.WebSocketResponseEvent) {
			mu.Lock()
			defer mu.Unlock()
			if strings.Contains(string(ev.Payload), "-delta") {
				observed = append(observed, ev.EventType+":"+strings.SplitN(strings.SplitN(string(ev.Payload), `"delta":"`, 2)[1], `"`, 2)[0])
				return
			}
			observed = append(observed, ev.EventType)
		},
	})
	if err != nil || result == nil {
		t.Fatalf("refusal after response.created must fail over to the next credential: result=%v err=%v", result, err)
	}
	if refusedAttempts.Load() != 1 || servedAttempts.Load() != 1 {
		t.Fatalf("attempts refused=%d served=%d, want 1,1", refusedAttempts.Load(), servedAttempts.Load())
	}

	// next returns the next payload, failing if the upstream would have to send more first.
	next := func(want string) string {
		t.Helper()
		select {
		case chunk, ok := <-result.Chunks:
			if !ok {
				t.Fatalf("stream closed while waiting for %s", want)
			}
			if chunk.Err != nil {
				t.Fatalf("stream error while waiting for %s: %v", want, chunk.Err)
			}
			return string(chunk.Payload)
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not stream at once", want)
		}
		return ""
	}
	var seen []string
	waitFor := func(marker string) {
		t.Helper()
		for {
			payload := next(marker)
			seen = append(seen, payload)
			if strings.Contains(payload, "resp_off") && strings.Contains(payload, `"status":"failed"`) {
				t.Fatalf("refused attempt leaked to the client: %s", payload)
			}
			if strings.Contains(payload, marker) {
				return
			}
		}
	}
	waitFor("first-delta")  // released by the first output frame, while upstream holds delta2
	openFirst()             // upstream may now send delta2
	waitFor("second-delta") // must arrive while upstream still holds response.completed
	openSecond()
	waitFor(`"response.completed"`)
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream error after completion: %v", chunk.Err)
		}
	}
	joined := strings.Join(seen, "\n")
	if strings.Index(joined, `"response.created"`) > strings.Index(joined, "first-delta") {
		t.Fatalf("held response.created was not released before the first delta: %s", joined)
	}

	mu.Lock()
	defer mu.Unlock()
	// The refused attempt never verified a client-visible stream, but its frames were observed
	// as they arrived; the served attempt must be observed completely and in order.
	served := observed
	for i := len(observed) - 1; i >= 0; i-- {
		if observed[i] == "response.created" {
			served = observed[i:]
			break
		}
	}
	want := []string{"response.created", "response.output_text.delta:first-delta", "response.output_text.delta:second-delta", "response.completed"}
	if !reflect.DeepEqual(served, want) {
		t.Fatalf("observed served events = %v (all %v), want %v", served, observed, want)
	}
}
