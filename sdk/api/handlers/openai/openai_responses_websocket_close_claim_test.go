package openai

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// Gate the actual Gorilla network writes: handshake, in-flight data frame, then
// terminal frame. The terminal write can only be released by transport Close.
// Small frames and explicit gates avoid relying on TCP buffer sizes or sleeps
// to establish that the terminal writer has acquired writeMu and stalled.
type closeClaimConn struct {
	net.Conn
	writes          atomic.Int32
	dataStarted     chan struct{}
	dataRelease     chan struct{}
	terminalStarted chan struct{}
	closed          chan struct{}
	closeOnce       sync.Once
}

func (c *closeClaimConn) Write(p []byte) (int, error) {
	switch c.writes.Add(1) {
	case 2:
		close(c.dataStarted)
		select {
		case <-c.dataRelease:
		case <-c.closed:
			return 0, net.ErrClosed
		}
	case 3:
		close(c.terminalStarted)
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Write(p)
}

func (c *closeClaimConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

type closeClaimListener struct {
	net.Listener
	conn *closeClaimConn
}

func (l closeClaimListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.conn.Conn = conn
	return l.conn, nil
}

func TestResponsesWebsocketDataAndPingObserveTerminalCloseClaim(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"data", "ping"} {
		for _, waiting := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/waiting=%t", path, waiting), func(t *testing.T) {
				gated := &closeClaimConn{
					dataStarted: make(chan struct{}), dataRelease: make(chan struct{}),
					terminalStarted: make(chan struct{}), closed: make(chan struct{}),
				}
				serverErrCh := make(chan error, 1)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					serverErrCh <- func() error {
						conn, err := responsesWebsocketUpgrader.Upgrade(w, r, nil)
						if err != nil {
							return err
						}
						var writers sync.WaitGroup
						defer func() {
							_ = conn.Close()
							writers.Wait() // join fixture goroutines on RED as well as GREEN
						}()
						writer := newResponsesWebsocketWriter(conn)
						frameDone := make(chan error, 1)
						writers.Add(1)
						go func() {
							defer writers.Done()
							frameDone <- writeResponsesWebsocketPayload(writer, nil, []byte(`{"type":"response.created"}`), time.Now())
						}()
						select {
						case <-gated.dataStarted:
						case <-time.After(2 * time.Second):
							return errors.New("in-flight frame did not reach network write")
						}

						forwardDone := make(chan error, 1)
						handlerDone := make(chan struct{})
						startHandler := func() {
							writers.Add(1)
							go func() {
								defer writers.Done()
								defer close(handlerDone)
								ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
								ctx.Request = r
								data := make(chan []byte, 1)
								opts := responsesWebsocketForwardOptions{}
								if path == "data" {
									data <- []byte(`{"type":"response.output_text.delta","delta":"later"}`)
								} else {
									interval := time.Millisecond
									opts.keepAliveInterval = &interval
								}
								h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, nil))
								_, _, _, _, errForward := h.forwardResponsesWebsocket(ctx, writer, func(...interface{}) {}, data, make(chan *interfaces.ErrorMessage), nil, "session-close-claim", opts)
								forwardDone <- errForward
								// The same terminal wait and Close as session teardown.
								writer.awaitTerminalWrite()
								_ = conn.Close()
							}()
						}
						if waiting {
							startHandler()
							// Negative bound: an ordinary writer must wait while the
							// frame is in flight and no close has been claimed yet.
							select {
							case errForward := <-forwardDone:
								return fmt.Errorf("writer returned before close claim: %v", errForward)
							case <-time.After(20 * time.Millisecond):
							}
						}

						terminalDone := make(chan struct{})
						writers.Add(1)
						go func() {
							defer writers.Done()
							writer.closeForUpstreamDisconnect(websocketPinnedFailoverStatusError{status: http.StatusBadRequest, msg: `{"error":{"type":"invalid_request_error","code":"fixture_terminal_refusal","message":"refused"}}`})
							close(terminalDone)
						}()
						claimDeadline := time.Now().Add(time.Second)
						for !writer.closing.Load() {
							if time.Now().After(claimDeadline) {
								return errors.New("terminal writer did not claim closing")
							}
							time.Sleep(time.Millisecond)
						}
						if waiting {
							// A pre-claim check followed by unconditional Lock fails
							// here: closing must release waiters before writeMu does.
							select {
							case errForward := <-forwardDone:
								if !errors.Is(errForward, websocket.ErrCloseSent) {
									return fmt.Errorf("waiting writer error = %v, want ErrCloseSent", errForward)
								}
							case <-time.After(100 * time.Millisecond):
								return errors.New("waiting writer did not observe close claim before the in-flight frame released writeMu")
							}
						}
						close(gated.dataRelease)
						if errFrame := <-frameDone; errFrame != nil {
							return fmt.Errorf("in-flight frame: %w", errFrame)
						}
						select {
						case <-gated.terminalStarted:
						case <-time.After(websocketTerminalPayloadWait):
							return errors.New("terminal write did not take over from in-flight frame")
						}
						select {
						case <-terminalDone:
							return errors.New("terminal write did not stall until teardown Close")
						default:
						}
						if !waiting {
							startHandler()
						}
						// Production teardown waits at most 500ms; allow 250ms
						// scheduler slack, not an unbounded network write.
						bound := time.NewTimer(3 * websocketTerminalPayloadWait)
						defer bound.Stop()
						select {
						case <-handlerDone:
						case <-bound.C:
							return errors.New("later writer and teardown blocked past 750ms behind stalled terminal write")
						}
						if !waiting {
							if errForward := <-forwardDone; !errors.Is(errForward, websocket.ErrCloseSent) {
								return fmt.Errorf("later writer error = %v, want ErrCloseSent", errForward)
							}
						}
						select {
						case <-terminalDone:
							return nil
						case <-bound.C:
							return errors.New("teardown Close did not release stalled terminal write within the same bound")
						}
					}()
				}))
				server.Listener = closeClaimListener{Listener: server.Listener, conn: gated}
				server.Start()
				defer server.Close()
				conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
				if err != nil {
					t.Fatalf("dial websocket: %v", err)
				}
				defer func() { _ = conn.Close() }()
				if errServer := <-serverErrCh; errServer != nil {
					t.Fatal(errServer)
				}
			})
		}
	}
}
