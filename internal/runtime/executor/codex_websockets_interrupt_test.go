package executor

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

func TestInterruptExecutionSessionRequiresActiveRead(t *testing.T) {
	received := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, payload, errRead := conn.ReadMessage()
		if errRead != nil {
			return
		}
		received <- payload
	}))
	defer upstream.Close()

	client, _, errDial := websocket.DefaultDialer.Dial("ws"+upstream.URL[len("http"):], nil)
	if errDial != nil {
		t.Fatal(errDial)
	}
	defer func() { _ = client.Close() }()

	const sessionID = "interrupt-requires-active-read"
	executor := NewCodexWebsocketsExecutor(nil)
	defer executor.CloseExecutionSession(sessionID)
	sess := executor.getOrCreateSession(sessionID)
	sess.connMu.Lock()
	sess.conn = client
	sess.authID = "account-user@private.example.json"
	sess.wsURL = upstream.URL + "/responses?token=synthetic-url-secret"
	sess.connMu.Unlock()

	interrupt := []byte(`{"type":"response.interrupt","response_id":"r1","mode":"discard_partial_items"}`)
	errIdle := executor.InterruptExecutionSession(context.Background(), sessionID, interrupt)
	if !errors.Is(errIdle, cliproxyexecutor.ErrNoActiveUpstreamWebsocket) {
		t.Fatalf("idle socket error = %v, want ErrNoActiveUpstreamWebsocket", errIdle)
	}
	select {
	case payload := <-received:
		t.Fatalf("idle socket was written: %s", payload)
	case <-time.After(200 * time.Millisecond):
	}

	readCh := sess.activate(client)
	defer sess.clearActive(client, readCh)
	var logs bytes.Buffer
	previousOutput, previousLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&logs)
	log.SetLevel(log.InfoLevel)
	defer func() {
		log.SetOutput(previousOutput)
		log.SetLevel(previousLevel)
	}()
	const requestID = "01234567-89ab-4cde-8f01-23455678abcd"
	ctx := logging.WithRequestID(context.Background(), requestID)
	if errActive := executor.InterruptExecutionSession(ctx, sessionID, interrupt); errActive != nil {
		t.Fatal(errActive)
	}
	logged := logs.String()
	for _, sensitive := range []string{"account-user", "private.example", upstream.URL, "synthetic-url-secret"} {
		if strings.Contains(logged, sensitive) {
			t.Errorf("interrupt log exposed sensitive value %q: %s", sensitive, logged)
		}
	}
	if strings.Contains(logged, sessionID) {
		t.Errorf("interrupt log exposed the raw session identity: %s", logged)
	}
	if !strings.Contains(logged, "event=response.interrupt") || !strings.Contains(logged, "session=[REDACTED]") || !strings.Contains(logged, logging.ShortRequestID(requestID)) {
		t.Errorf("interrupt log lost safe control/request correlation: %s", logged)
	}
	select {
	case payload := <-received:
		if !bytes.Equal(payload, interrupt) {
			t.Fatalf("active interrupt = %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active socket did not receive the interrupt")
	}
}
