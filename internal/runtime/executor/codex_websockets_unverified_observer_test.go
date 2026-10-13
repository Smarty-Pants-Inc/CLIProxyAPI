package executor

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// With no observer configured, unverified frames are bounded but never copied.
func TestCodexUnverifiedObserverEvents_NoObserverRetainsNothing(t *testing.T) {
	var u codexUnverifiedObserverEvents
	for i := 0; i < 3; i++ {
		if !u.retain(false, []byte(`{"type":"response.in_progress","response":{"id":"resp_1"}}`)) {
			t.Fatalf("frame %d under the bound was refused", i)
		}
	}
	if u.events != nil {
		t.Fatalf("no observer: retained %d copies, want none", len(u.events))
	}
	if u.frames != 3 || u.bytes == 0 {
		t.Fatalf("no observer: bound not accounted: frames=%d bytes=%d", u.frames, u.bytes)
	}
	if got := u.take(); got != nil {
		t.Fatalf("take() = %d events, want none", len(got))
	}
}

// The byte bound is checked before the copy: an over-bound frame is refused and nothing is added.
func TestCodexUnverifiedObserverEvents_ByteCapBeforeClone(t *testing.T) {
	var u codexUnverifiedObserverEvents
	small := []byte(`{"type":"response.created","response":{"id":"resp_1"}}`)
	if !u.retain(true, small) || len(u.events) != 1 {
		t.Fatalf("small frame not retained: %d", len(u.events))
	}
	fill := make([]byte, codexBootstrapMaxBufferedBytes-len(small))
	if !u.retain(true, fill) {
		t.Fatal("frame that reaches the bound exactly was refused")
	}
	if u.retain(true, []byte("x")) {
		t.Fatal("frame past the 1 MiB bound was retained")
	}
	if len(u.events) != 2 || u.bytes != codexBootstrapMaxBufferedBytes {
		t.Fatalf("refused frame changed the retained state: events=%d bytes=%d", len(u.events), u.bytes)
	}
	var v codexUnverifiedObserverEvents
	if v.retain(true, make([]byte, codexBootstrapMaxBufferedBytes+1)) || v.events != nil || v.bytes != 0 {
		t.Fatalf("oversized first frame was copied or counted: events=%d bytes=%d", len(v.events), v.bytes)
	}
	var w codexUnverifiedObserverEvents
	for i := 0; i < codexBootstrapMaxBufferedFrames; i++ {
		if !w.retain(true, []byte("{}")) {
			t.Fatalf("frame %d under the frame bound was refused", i)
		}
	}
	if w.retain(true, []byte("{}")) || len(w.events) != codexBootstrapMaxBufferedFrames {
		t.Fatalf("frame past the frame bound was retained: %d", len(w.events))
	}
}

// End to end: an oversized frame before identity fails the attempt closed; neither the observer
// nor the client sees any unverified event, even though a verifying frame follows.
func TestCodexWebsocketsExecutor_OversizedPreIdentityFrameFailsClosed(t *testing.T) {
	oversized := `{"type":"response.in_progress","response":{"id":"` + strings.Repeat("q", codexBootstrapMaxBufferedBytes+1) + `"}}`
	server := codexWebsocketServer(t, oversized, codexCreatedEvent, codexObserverCompletedEvent)
	defer server.Close()
	var observed atomic.Int32
	req, opts := codexWebsocketRequest()
	opts.WebSocketResponseObserver = func(context.Context, cliproxyexecutor.WebSocketResponseEvent) { observed.Add(1) }
	for _, tc := range []struct {
		name string
		cfg  bool
	}{{"default", false}, {"explicit_off", true}} {
		t.Run(tc.name, func(t *testing.T) {
			observed.Store(0)
			exec := NewCodexWebsocketsExecutor(nil)
			if tc.cfg {
				exec = NewCodexWebsocketsExecutor(codexBufferingExplicitlyOffConfig())
			}
			result, err := exec.ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
			if result != nil || err == nil {
				t.Fatalf("ExecuteStream = %v, %v; want fail-closed with no stream", result, err)
			}
			if n := observed.Load(); n != 0 {
				t.Fatalf("observer received %d unverified events, want 0", n)
			}
		})
	}
}
