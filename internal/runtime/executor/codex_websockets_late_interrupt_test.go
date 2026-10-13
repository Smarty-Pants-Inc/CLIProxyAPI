package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Exercise terminal recording through the wire, not a separate test-only insertion path.
func TestCodexWebsocketSessionBoundsTerminalResponseIDs(t *testing.T) {
	const limit = 1024
	const total = 10000
	upstreamConn := make(chan *websocket.Conn, 1)
	// Keep a broken implementation that forwards recent IDs from blocking cleanup.
	received := make(chan string, 2*limit+8)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		upstreamConn <- conn
		for {
			_, payload, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			received <- string(payload)
		}
	}))
	defer upstream.Close()
	client, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	exec := NewCodexWebsocketsExecutor(nil)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	const sessionID = "bounded-terminal-ids"
	defer exec.CloseExecutionSession(sessionID)
	sess := exec.getOrCreateSession(sessionID)
	sess.conn = client
	sess.connCloser = newWebsocketConnectionCloser(client)
	sess.configureConn(client)
	readCh := sess.activate(client)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		exec.readUpstreamLoop(sess, client)
	}()
	server := <-upstreamConn
	writeTerminal := func(id string) {
		t.Helper()
		payload := []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q}}`, id))
		if errWrite := server.WriteMessage(websocket.TextMessage, payload); errWrite != nil {
			t.Fatal(errWrite)
		}
		select {
		case event := <-readCh:
			if event.err != nil || string(event.payload) != string(payload) {
				t.Fatalf("terminal read = %+v, want %s", event, payload)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("terminal read timed out")
		}
	}
	interrupt := func(id string) error {
		return exec.InterruptExecutionSession(context.Background(), sessionID,
			[]byte(fmt.Sprintf(`{"type":"response.interrupt","response_id":%q}`, id)))
	}
	maxSize := 0
	for i := 0; i < total; i++ {
		writeTerminal(fmt.Sprintf("response-%d", i))
		sess.activeMu.Lock()
		size := len(sess.terminalResponseIDs)
		sess.activeMu.Unlock()
		if size > maxSize {
			maxSize = size
		}
	}
	if maxSize != limit {
		t.Errorf("maximum terminal set size = %d, want %d after %d responses", maxSize, limit, total)
	}
	sess.clearActive(client, readCh)
	for i := total - limit; i < total; i++ {
		if errInterrupt := interrupt(fmt.Sprintf("response-%d", i)); errInterrupt != nil {
			t.Fatalf("recent terminal response-%d interrupt = %v", i, errInterrupt)
		}
	}
	for _, id := range []string{"response-0", "response-8975", "unknown"} {
		if errInterrupt := interrupt(id); errInterrupt != cliproxyexecutor.ErrNoActiveUpstreamWebsocket {
			t.Fatalf("idle %s interrupt = %v, want exact ErrNoActiveUpstreamWebsocket", id, errInterrupt)
		}
	}
	// Duplicate terminal events must not consume slots or evict other recent IDs.
	readCh = sess.activate(client)
	for i := 0; i < limit; i++ {
		writeTerminal("response-9999")
	}
	writeTerminal("response-10000")
	if errInterrupt := interrupt("response-8977"); errInterrupt != nil {
		t.Fatalf("duplicates evicted a recent terminal: %v", errInterrupt)
	}
	if errInterrupt := interrupt("response-9999"); errInterrupt != nil {
		t.Fatalf("late interrupt during next turn: %v", errInterrupt)
	}
	// Evicted IDs retain unknown-ID behavior even with an active turn: forward
	// their original control frame, not a local acknowledgement or rejection.
	for _, id := range []string{"response-8976", "unknown"} {
		if errInterrupt := interrupt(id); errInterrupt != nil {
			t.Fatalf("active %s interrupt = %v", id, errInterrupt)
		}
	}
	if errWrite := client.WriteMessage(websocket.TextMessage, []byte("barrier")); errWrite != nil {
		t.Fatal(errWrite)
	}
	for _, want := range []string{
		`{"type":"response.interrupt","response_id":"response-8976"}`,
		`{"type":"response.interrupt","response_id":"unknown"}`,
		"barrier",
	} {
		select {
		case got := <-received:
			if got != want {
				t.Fatalf("upstream control = %s, want %s", got, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("upstream control timed out")
		}
	}
	sess.clearActive(client, readCh)
	// Reusing the same connection preserves the window; installing a different
	// connection clears both membership and insertion order.
	sess.resetTerminalError(client)
	if errInterrupt := interrupt("response-10000"); errInterrupt != nil {
		t.Fatalf("same-connection reset lost recent ID: %v", errInterrupt)
	}
	if errClose := sess.connCloser.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	select {
	case <-readerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("old reader did not stop")
	}
	nextConn, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	sess.connMu.Lock()
	sess.conn = nextConn
	sess.connCloser = newWebsocketConnectionCloser(nextConn)
	sess.connMu.Unlock()
	sess.configureConn(nextConn)
	if errInterrupt := interrupt("response-10000"); errInterrupt != cliproxyexecutor.ErrNoActiveUpstreamWebsocket {
		t.Fatalf("reconnected old terminal interrupt = %v, want exact ErrNoActiveUpstreamWebsocket", errInterrupt)
	}
	readCh = sess.activate(nextConn)
	go exec.readUpstreamLoop(sess, nextConn)
	server = <-upstreamConn
	// Fill the new window to expose stale insertion-order entries after reset.
	for i := 0; i < limit; i++ {
		writeTerminal(fmt.Sprintf("new-response-%d", i))
	}
	sess.clearActive(nextConn, readCh)
	for i := 0; i < limit; i++ {
		if errInterrupt := interrupt(fmt.Sprintf("new-response-%d", i)); errInterrupt != nil {
			t.Fatalf("new-connection terminal response-%d interrupt = %v", i, errInterrupt)
		}
	}
	sess.activeMu.Lock()
	resetSize := len(sess.terminalResponseIDs)
	sess.activeMu.Unlock()
	if resetSize != limit {
		t.Fatalf("new-connection set size = %d, want %d", resetSize, limit)
	}
}

// A completion arriving while credential validation is in progress must be
// reflected in the interrupt decision, not forwarded into the following turn.
func TestInterruptExecutionSessionCompletesDuringAuthCheck(t *testing.T) {
	complete := make(chan struct{})
	interruptCount := make(chan int, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade: %v", errUpgrade)
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Errorf("close upstream: %v", errClose)
			}
		}()
		<-complete
		if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"r1","output":[]}}`)); errWrite != nil {
			t.Errorf("write completion: %v", errWrite)
			return
		}
		count := 0
		for {
			_, payload, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			if string(payload) == "barrier" {
				interruptCount <- count
				return
			}
			count++
		}
	}))
	defer upstream.Close()
	client, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	exec := NewCodexWebsocketsExecutor(nil)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	const sessionID = "completion-during-auth-check"
	defer exec.CloseExecutionSession(sessionID)
	sess := exec.getOrCreateSession(sessionID)
	sess.conn = client
	sess.connCloser = newWebsocketConnectionCloser(client)
	sess.configureConn(client)
	readCh := sess.activate(client)
	go exec.readUpstreamLoop(sess, client)
	ctx := cliproxyexecutor.WithWebsocketAuthCheck(context.Background(), func(string) bool {
		close(complete)
		select {
		case event := <-readCh:
			if event.err != nil {
				t.Fatal(event.err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("completion timed out")
		}
		sess.clearActive(client, readCh)
		return true
	})
	if errInterrupt := exec.InterruptExecutionSession(ctx, sessionID, []byte(`{"type":"response.interrupt","response_id":"r1"}`)); errInterrupt != nil {
		t.Fatalf("completed interrupt = %v", errInterrupt)
	}
	// A transport-order barrier avoids sleeps or assumptions about whether the
	// upstream reader has already consumed a wrongly forwarded interrupt.
	if errWrite := client.WriteMessage(websocket.TextMessage, []byte("barrier")); errWrite != nil {
		t.Fatal(errWrite)
	}
	select {
	case count := <-interruptCount:
		if count != 0 {
			t.Fatalf("forwarded %d interrupt(s) after the response became terminal", count)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("upstream barrier timed out")
	}
}

// Clearing a completed turn must not turn its delayed interrupt into an error,
// or forward it into the next response on the retained upstream socket.
func TestInterruptExecutionSessionAfterTerminal(t *testing.T) {
	for _, terminal := range []string{"response.completed", "response.done", "response.incomplete", "response.failed"} {
		t.Run(terminal, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if errUpgrade != nil {
					t.Errorf("upgrade: %v", errUpgrade)
					return
				}
				defer func() {
					if errClose := conn.Close(); errClose != nil {
						t.Errorf("close upstream: %v", errClose)
					}
				}()
				for _, payload := range []string{
					`{"type":"response.created","response":{"id":"r1"}}`,
					`{"type":"` + terminal + `","response":{"id":"r1","output":[]}}`,
				} {
					if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(payload)); errWrite != nil {
						t.Errorf("write: %v", errWrite)
						return
					}
				}
				// The only forwarded interrupt must target the active r2, not r1.
				_, payload, errRead := conn.ReadMessage()
				if errRead != nil {
					return
				}
				if string(payload) != `{"type":"response.interrupt","response_id":"r2"}` {
					t.Errorf("late interrupt contaminated next response: %s", payload)
				}
				if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.incomplete","response":{"id":"r2"}}`)); errWrite != nil {
					t.Errorf("write r2 terminal: %v", errWrite)
				}
				_, _, _ = conn.ReadMessage()
			}))
			defer upstream.Close()
			client, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
			if errDial != nil {
				t.Fatal(errDial)
			}
			exec := NewCodexWebsocketsExecutor(nil)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			const sessionID = "late-interrupt"
			defer exec.CloseExecutionSession(sessionID)
			sess := exec.getOrCreateSession(sessionID)
			sess.conn = client
			sess.connCloser = newWebsocketConnectionCloser(client)
			sess.configureConn(client)
			readCh := sess.activate(client)
			go exec.readUpstreamLoop(sess, client)
			read := func() codexWebsocketRead {
				t.Helper()
				select {
				case event := <-readCh:
					if event.err != nil {
						t.Fatal(event.err)
					}
					return event
				case <-time.After(3 * time.Second):
					t.Fatal("upstream event timed out")
					return codexWebsocketRead{}
				}
			}
			read()
			read()
			sess.clearActive(client, readCh)
			late := []byte(`{"type":"response.interrupt","response_id":"r1"}`)
			for i := 0; i < 2; i++ {
				if errInterrupt := exec.InterruptExecutionSession(context.Background(), sessionID, late); errInterrupt != nil {
					t.Fatalf("terminal r1 interrupt %d must be idempotent, got %v", i+1, errInterrupt)
				}
			}
			unknown := []byte(`{"type":"response.interrupt","response_id":"unknown"}`)
			if errUnknown := exec.InterruptExecutionSession(context.Background(), sessionID, unknown); !errors.Is(errUnknown, cliproxyexecutor.ErrNoActiveUpstreamWebsocket) {
				t.Fatalf("unknown idle interrupt = %v, want ErrNoActiveUpstreamWebsocket for local HTTP fallback", errUnknown)
			}
			readCh = sess.activate(client)
			if errLate := exec.InterruptExecutionSession(context.Background(), sessionID, late); errLate != nil {
				t.Fatalf("late r1 during r2 = %v", errLate)
			}
			if errActive := exec.InterruptExecutionSession(context.Background(), sessionID, []byte(`{"type":"response.interrupt","response_id":"r2"}`)); errActive != nil {
				t.Fatal(errActive)
			}
			read()
			sess.clearActive(client, readCh)
			for _, id := range []string{"r1", "r2"} {
				if errLate := exec.InterruptExecutionSession(context.Background(), sessionID, []byte(`{"type":"response.interrupt","response_id":"`+id+`"}`)); errLate != nil {
					t.Fatalf("earlier terminal %s = %v", id, errLate)
				}
			}
			if errWrite := client.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "test disconnect")); errWrite != nil {
				t.Fatal(errWrite)
			}
			select {
			case <-sess.upstreamDisconnectCh:
			case <-time.After(3 * time.Second):
				t.Fatal("real disconnect was not reported")
			}
			if errDisconnected := exec.InterruptExecutionSession(context.Background(), sessionID, []byte(`{"type":"response.interrupt","response_id":"r2"}`)); !errors.Is(errDisconnected, cliproxyexecutor.ErrNoActiveUpstreamWebsocket) {
				t.Fatalf("disconnected interrupt = %v, want ErrNoActiveUpstreamWebsocket", errDisconnected)
			}
		})
	}
}
