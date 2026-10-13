package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// codexBufferingExplicitlyOffConfig is the config a YAML `stream-bootstrap-buffering: false`
// produces. A zero config (key absent) keeps the default hold.
func codexBufferingExplicitlyOffConfig() *config.Config {
	return &config.Config{Codex: config.CodexConfig{StreamBootstrapBuffering: false, StreamBootstrapBufferingSet: true}}
}

// heldUpstream releases its handler (and so the connection) once; tests release it on exit.
type heldUpstream struct {
	gate chan struct{}
	once sync.Once
}

func newHeldUpstream() *heldUpstream { return &heldUpstream{gate: make(chan struct{})} }
func (h *heldUpstream) release()     { h.once.Do(func() { close(h.gate) }) }

// heldSSEServer writes the frames, then holds the response open until released, then writes tail.
func heldSSEServer(h *heldUpstream, frames []string, tail ...string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		for _, frame := range frames {
			_, _ = w.Write([]byte("data: " + frame + "\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
		<-h.gate
		for _, frame := range tail {
			_, _ = w.Write([]byte("data: " + frame + "\n\n"))
		}
	}))
}

// heldWebsocketServer writes the frames, then holds the socket open until released, then writes tail.
func heldWebsocketServer(t *testing.T, h *heldUpstream, frames []string, tail ...string) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("upgrade websocket: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, errRead := conn.ReadMessage(); errRead != nil {
			t.Errorf("read websocket request: %v", errRead)
			return
		}
		for _, frame := range frames {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(frame))
		}
		<-h.gate
		for _, frame := range tail {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(frame))
		}
	}))
}

type streamOutcome struct {
	result *cliproxyexecutor.StreamResult
	err    error
}

func startStream(run func(context.Context) (*cliproxyexecutor.StreamResult, error)) (<-chan streamOutcome, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ch := make(chan streamOutcome, 1)
	go func() {
		result, err := run(ctx)
		ch <- streamOutcome{result, err}
	}()
	return ch, cancel
}

// assertReleasedAfterIdentity checks that the downstream has the stream, with response.created as
// its first chunk, while the upstream is still held after the verified identity frame and has not
// produced any generated output.
func assertReleasedAfterIdentity(t *testing.T, ch <-chan streamOutcome) {
	t.Helper()
	var outcome streamOutcome
	select {
	case outcome = <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("explicit off: stream was not released after the verified identity frame")
	}
	if outcome.err != nil || outcome.result == nil {
		t.Fatalf("explicit off: ExecuteStream = %v, %v; want a released stream", outcome.result, outcome.err)
	}
	select {
	case chunk := <-outcome.result.Chunks:
		if chunk.Err != nil || !strings.Contains(string(chunk.Payload), "response.created") {
			t.Fatalf("first chunk = %s / %v, want response.created", chunk.Payload, chunk.Err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("explicit off: response.created did not reach the downstream before generated output")
	}
}

// assertHeld checks that the default config still holds the same upstream (the counterexample).
func assertHeld(t *testing.T, ch <-chan streamOutcome) {
	t.Helper()
	select {
	case outcome := <-ch:
		t.Fatalf("default config released before the first output: result=%v err=%v", outcome.result, outcome.err)
	case <-time.After(200 * time.Millisecond):
	}
}

// Held-upstream regression, HTTP/SSE: explicit off releases right after the verified identity.
func TestCodexExecutor_BootstrapBufferingExplicitOff_ReleasesAfterVerifiedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      *config.Config
		released bool
	}{{"explicit_off", codexBufferingExplicitlyOffConfig(), true}, {"default", &config.Config{}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHeldUpstream()
			server := heldSSEServer(h, []string{codexCreatedEvent})
			defer server.Close()
			defer h.release()
			req, opts := codexTestRequest()
			ch, cancel := startStream(func(ctx context.Context) (*cliproxyexecutor.StreamResult, error) {
				return NewCodexExecutor(tc.cfg).ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
			})
			defer cancel()
			if tc.released {
				assertReleasedAfterIdentity(t, ch)
			} else {
				assertHeld(t, ch)
			}
		})
	}
}

// Held-upstream regression, websocket: explicit off releases right after the verified identity.
func TestCodexWebsocketsExecutor_BootstrapBufferingExplicitOff_ReleasesAfterVerifiedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cfg      *config.Config
		released bool
	}{{"explicit_off", codexBufferingExplicitlyOffConfig(), true}, {"default", &config.Config{}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHeldUpstream()
			server := heldWebsocketServer(t, h, []string{codexCreatedEvent})
			defer server.Close()
			defer h.release()
			req, opts := codexWebsocketRequest()
			ch, cancel := startStream(func(ctx context.Context) (*cliproxyexecutor.StreamResult, error) {
				return NewCodexWebsocketsExecutor(tc.cfg).ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
			})
			defer cancel()
			if tc.released {
				assertReleasedAfterIdentity(t, ch)
			} else {
				assertHeld(t, ch)
			}
		})
	}
}

// Explicit off keeps the fail-closed hold before identity on websockets: output that arrives
// before the exact model is verified is not released.
func TestCodexWebsocketsExecutor_BootstrapBufferingExplicitOff_WithholdsBeforeIdentity(t *testing.T) {
	h := newHeldUpstream()
	server := heldWebsocketServer(t, h,
		[]string{codexOutputDeltaEvent},
		codexCreatedEvent, codexObserverCompletedEvent)
	defer server.Close()
	defer h.release()
	req, opts := codexWebsocketRequest()
	ch, cancel := startStream(func(ctx context.Context) (*cliproxyexecutor.StreamResult, error) {
		return NewCodexWebsocketsExecutor(codexBufferingExplicitlyOffConfig()).ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
	})
	defer cancel()
	select {
	case outcome := <-ch:
		t.Fatalf("stream became available before identity verification: result=%v err=%v", outcome.result, outcome.err)
	case <-time.After(200 * time.Millisecond):
	}
	h.release()
	outcome := <-ch
	if outcome.err != nil || outcome.result == nil {
		t.Fatalf("ExecuteStream after identity = %v, %v", outcome.result, outcome.err)
	}
	combined, streamErr := drainChunks(outcome.result)
	if streamErr != nil || !strings.Contains(combined, "response.created") || !strings.Contains(combined, `"delta":"hi"`) {
		t.Fatalf("verified stream = %s / %v; want the held delta and response.created", combined, streamErr)
	}
}

// The documented trade-off of opting out: a quota refusal after the release reaches the client
// in-stream and is not failed over. (The default fails over: QuotaBootstrapPreservesCooling.)
func TestCodexWebsocketsExecutor_BootstrapBufferingExplicitOff_RefusalAfterReleaseStaysInStream(t *testing.T) {
	refusal := `{"type":"response.failed","response":{"id":"resp_1","status":"failed","error":` + codexBootstrapQuotaError + `}}`
	server := codexWebsocketServer(t, codexCreatedEvent, refusal)
	defer server.Close()
	req, opts := codexWebsocketRequest()
	result, err := NewCodexWebsocketsExecutor(codexBufferingExplicitlyOffConfig()).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil || result == nil {
		t.Fatalf("ExecuteStream = %v, %v; want a released stream", result, err)
	}
	combined, streamErr := drainChunks(result)
	if !strings.Contains(combined, "response.created") {
		t.Fatalf("released handshake missing: %s", combined)
	}
	if streamErr == nil {
		t.Fatal("quota refusal after release must be delivered in-stream")
	}
	if got := statusCodeFromTestError(t, streamErr); got != http.StatusTooManyRequests {
		t.Fatalf("in-stream refusal status = %d, want 429", got)
	}
}
