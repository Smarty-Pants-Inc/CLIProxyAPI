package executor

import (
	"testing"
	"time"
)

func TestCodexWebsocketCloseArbitrationIdleDisconnect(t *testing.T) {
	c, exec, _ := arbitrationClient(t, "usage_limit_reached", true, nil)
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	sess := <-exec.session
	// Completion validation releases reqMu only after clearing the active request.
	sess.reqMu.Lock()
	defer sess.reqMu.Unlock()
	sess.connMu.Lock()
	upstream := sess.conn
	sess.connMu.Unlock()
	if upstream == nil {
		t.Fatal("replacement upstream not live")
	}
	if active, _ := sess.activeForConn(upstream); active != nil {
		t.Fatal("idle control still has an active request")
	}
	// Closing the transport produces EOF in the real reader while the real handler
	// is idle. Unlike an in-flight disconnect it must notify immediately, not hold.
	if err := upstream.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("idle upstream disconnect did not close downstream")
	} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		t.Fatal("idle disconnect waited for the decision bound")
	}
	sess.connMu.Lock()
	defer sess.connMu.Unlock()
	if sess.conn != nil || sess.readerConn != nil || sess.disconnectHold != nil {
		t.Fatal("idle disconnect leaked connection or decision timer")
	}
}
