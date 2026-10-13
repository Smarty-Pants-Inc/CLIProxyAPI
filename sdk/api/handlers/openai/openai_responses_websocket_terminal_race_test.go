package openai

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// ExecuteStreamWithAuthManager buffers a terminal error in errs and then closes
// data (and errs). When the forwarder is busy writing earlier frames, both select
// cases are ready at once; Go then picks at random. Picking the closed data
// channel first dropped the typed error and closed the socket without it.
func TestForwardResponsesWebsocketPrefersBufferedTerminalErrorOverDataClose(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for i := 0; i < 64; i++ {
		serverErrCh := make(chan error, 1)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := responsesWebsocketUpgrader.Upgrade(w, r, nil)
			if err != nil {
				serverErrCh <- err
				return
			}
			defer func() { _ = conn.Close() }()
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = r
			data := make(chan []byte)
			errCh := make(chan *interfaces.ErrorMessage, 1)
			errCh <- &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: websocketPinnedFailoverStatusError{status: http.StatusBadRequest, msg: "compaction_json_rejected: fixture refusal"}}
			close(errCh)
			close(data)
			h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, nil))
			_, _, _, errMsg, _ := h.forwardResponsesWebsocket(ctx, newResponsesWebsocketWriter(conn), func(...interface{}) {}, data, errCh, newInMemoryWebsocketTimelineLog(), "session-race")
			if errMsg == nil || errMsg.StatusCode != http.StatusBadRequest {
				serverErrCh <- fmt.Errorf("forward error message = %#v, want the buffered 400 refusal", errMsg)
				return
			}
			serverErrCh <- nil
		}))
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
		if err != nil {
			server.Close()
			t.Fatalf("dial websocket: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		messageType, payload, errRead := conn.ReadMessage()
		_ = conn.Close()
		errServer := <-serverErrCh
		server.Close()
		if errServer != nil {
			t.Fatalf("iteration %d: %v", i, errServer)
		}
		var closeErr *websocket.CloseError
		if errRead != nil || messageType != websocket.TextMessage || !strings.Contains(string(payload), "compaction_json_rejected") {
			t.Fatalf("iteration %d: downstream got type=%d payload=%q err=%v (close=%v), want the typed error frame", i, messageType, payload, errRead, errors.As(errRead, &closeErr))
		}
	}
}

// The upstream-disconnect path writes the typed terminal error from its own
// goroutine. When the forwarder was mid-frame (writeMu held), it closed the
// socket without the error and set closing, so neither side delivered it. Then
// the data writer's return let session teardown close the socket under the
// error write. Observed on the real binary: 1-5 of 200 sessions ended with EOF.
func TestResponsesWebsocketDisconnectErrorWaitsForInFlightFrame(t *testing.T) {
	serverErrCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := responsesWebsocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrCh <- err
			return
		}
		writer := newResponsesWebsocketWriter(conn)
		writer.writeMu.Lock() // a data frame is being written
		done := make(chan struct{})
		go func() {
			writer.closeForUpstreamDisconnect(websocketPinnedFailoverStatusError{status: http.StatusBadRequest, msg: `{"error":{"type":"invalid_request_error","code":"fixture_terminal_refusal","message":"refused"}}`})
			close(done)
		}()
		for !writer.closing.Load() {
			time.Sleep(time.Millisecond)
		}
		// The data writer finishes its frame, sees closing and returns; the
		// session then tears down at once, as the handler's defer does.
		writer.writeMu.Unlock()
		writer.awaitTerminalWrite()
		_ = conn.Close()
		select {
		case <-done:
			serverErrCh <- nil
		case <-time.After(2 * time.Second):
			serverErrCh <- errors.New("disconnect close did not finish")
		}
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	messageType, payload, errRead := conn.ReadMessage()
	if errRead != nil || messageType != websocket.TextMessage || !strings.Contains(string(payload), "fixture_terminal_refusal") {
		t.Fatalf("downstream got type=%d payload=%q err=%v, want the typed error frame", messageType, payload, errRead)
	}
	if errServer := <-serverErrCh; errServer != nil {
		t.Fatal(errServer)
	}
}

// With steering off, one Codex typed error reaches both terminal callers: the
// disconnect subscriber and the handler's forwarder. When the subscriber's
// terminal write stalls on a client that does not read, the handler's duplicate
// call waited on terminalMu forever, so its teardown (awaitTerminalWrite and
// conn.Close) never ran and the stalled writer was never released.
func TestResponsesWebsocketDuplicateTerminalCallDoesNotWaitOnStalledWriter(t *testing.T) {
	gin.SetMode(gin.TestMode)
	serverErrCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := responsesWebsocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			serverErrCh <- err
			return
		}
		defer func() { _ = conn.Close() }()
		if tcp, ok := conn.UnderlyingConn().(*net.TCPConn); ok {
			_ = tcp.SetWriteBuffer(4096)
		}
		writer := newResponsesWebsocketWriter(conn)

		// The subscriber's terminal write: far larger than the socket buffers of
		// a client that never reads, so it stalls inside WriteMessage.
		firstDone := make(chan struct{})
		go func() {
			_, _ = writer.closeWithPayload(make([]byte, 32<<20))
			close(firstDone)
		}()
		for !writer.closing.Load() {
			time.Sleep(time.Millisecond)
		}

		// The handler's forwarder receives the same typed error.
		handlerDone := make(chan struct{})
		go func() {
			defer close(handlerDone)
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = r
			data := make(chan []byte)
			errCh := make(chan *interfaces.ErrorMessage, 1)
			errCh <- &interfaces.ErrorMessage{StatusCode: http.StatusBadRequest, Error: websocketPinnedFailoverStatusError{status: http.StatusBadRequest, msg: "compaction_json_rejected: fixture refusal"}}
			close(errCh)
			close(data)
			h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, nil))
			_, _, _, _, _ = h.forwardResponsesWebsocket(ctx, writer, func(...interface{}) {}, data, errCh, newInMemoryWebsocketTimelineLog(), "session-duplicate")
			// Session teardown, as the handler's defer does it.
			writer.awaitTerminalWrite()
			_ = conn.Close()
		}()

		select {
		case <-handlerDone:
		case <-time.After(2 * time.Second):
			_ = conn.Close() // release the fixture
			serverErrCh <- errors.New("duplicate terminal call and teardown did not return within 2s behind a stalled terminal writer")
			return
		}
		select {
		case <-firstDone:
			serverErrCh <- nil
		case <-time.After(2 * time.Second):
			serverErrCh <- errors.New("teardown close did not release the stalled terminal writer")
		}
	}))
	defer server.Close()
	dialer := *websocket.DefaultDialer
	dialer.NetDial = func(network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetReadBuffer(4096)
		}
		return c, err
	}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer func() { _ = conn.Close() }()
	// The client does not read, so the first terminal write cannot finish.
	if errServer := <-serverErrCh; errServer != nil {
		t.Fatal(errServer)
	}
}
