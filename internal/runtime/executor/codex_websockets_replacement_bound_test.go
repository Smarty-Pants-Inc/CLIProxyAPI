package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCodexSessionSurvivesExecutorReplacementWithBoundedTerminalIDs(t *testing.T) {
	const limit = 1024
	serverConn := make(chan *websocket.Conn, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		serverConn <- conn
		_, _, _ = conn.ReadMessage()
	}))
	defer upstream.Close()
	client, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(upstream.URL, "http"), nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	store := &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	old := NewCodexAutoExecutor(nil)
	old.wsExec.store = store
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(old)
	const sessionID = "replacement-bounded-ids"
	defer old.CloseExecutionSession(sessionID)
	sess := old.wsExec.getOrCreateSession(sessionID)
	sess.conn = client
	sess.connCloser = newWebsocketConnectionCloser(client)
	sess.configureConn(client)
	readCh := sess.activate(client)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); old.wsExec.readUpstreamLoop(sess, client) }()
	server := <-serverConn
	writeTerminal := func(i int) {
		t.Helper()
		payload := []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"replacement-%d"}}`, i))
		if err := server.WriteMessage(websocket.TextMessage, payload); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-readCh:
			if event.err != nil || string(event.payload) != string(payload) {
				t.Fatalf("terminal read = %+v", event)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("terminal event timed out")
		}
		sess.activeMu.Lock()
		size := len(sess.terminalResponseIDs)
		sess.activeMu.Unlock()
		if size > limit {
			t.Fatalf("retained %d terminal IDs, limit %d", size, limit)
		}
	}
	for i := 0; i < limit; i++ {
		writeTerminal(i)
	}
	next := NewCodexAutoExecutor(nil)
	next.wsExec.store = store
	manager.RegisterExecutor(next)
	if next.wsExec.getOrCreateSession(sessionID) != sess {
		t.Fatal("executor replacement discarded the shared session")
	}
	sess.connMu.Lock()
	retainedConn := sess.conn
	sess.connMu.Unlock()
	if retainedConn != client {
		t.Fatal("executor replacement closed the live connection")
	}
	for i := limit; i < 3*limit; i++ {
		writeTerminal(i)
	}
	sess.clearActive(client, readCh)
	for i := 2 * limit; i < 3*limit; i++ {
		payload := []byte(fmt.Sprintf(`{"type":"response.interrupt","response_id":"replacement-%d"}`, i))
		if err := next.wsExec.InterruptExecutionSession(context.Background(), sessionID, payload); err != nil {
			t.Fatalf("replacement lost recent terminal ID %d: %v", i, err)
		}
	}
	if err := next.wsExec.InterruptExecutionSession(context.Background(), sessionID, []byte(`{"type":"response.interrupt","response_id":"replacement-0"}`)); err != cliproxyexecutor.ErrNoActiveUpstreamWebsocket {
		t.Fatalf("replacement retained evicted ID: %v", err)
	}
	sess.activeMu.Lock()
	size := len(sess.terminalResponseIDs)
	sess.activeMu.Unlock()
	if size != limit {
		t.Fatalf("final retained IDs = %d, want %d", size, limit)
	}
	next.CloseExecutionSession(sessionID)
	select {
	case <-readerDone:
	case <-time.After(3 * time.Second):
		t.Fatal("session reader did not stop")
	}
}
