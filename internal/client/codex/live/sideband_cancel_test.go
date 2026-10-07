package live

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// All deadlines here are failure guards, never evidence of ordering or absence.
func waitLiveEvent(t *testing.T, event <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func TestSidebandDialerHasNoHandshakeTimeout(t *testing.T) {
	for _, proxy := range []string{"", "direct", "http://proxy.example:8080", "socks5://proxy.example:1080", "socks5h://proxy.example:1080"} {
		if d := newSidebandDialer(proxy); d.HandshakeTimeout != 0 {
			t.Errorf("proxy %q: HandshakeTimeout=%v, want no network timeout", proxy, d.HandshakeTimeout)
		}
	}
}

type deadlineRecordingConn struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

// Instead of waiting 30 seconds, mechanically prove that Gorilla receives no
// deadline and applies none to the TLS/HTTP transport, then cancel a real pending
// authenticated upgrade and wait for both the dial goroutine and socket to exit.
func TestSidebandDialPendingTLSUpgradeEndsOnContextCancel(t *testing.T) {
	arrived, gone, stall := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic" || !websocket.IsWebSocketUpgrade(r) {
			t.Error("missing authenticated upgrade")
		}
		close(arrived)
		select {
		case <-r.Context().Done():
			close(gone)
		case <-stall:
		}
	}))
	defer upstream.Close()
	defer close(stall)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dialer := newSidebandDialer("direct")
	if dialer.HandshakeTimeout != 0 {
		t.Fatalf("HandshakeTimeout=%v, want zero after credential acquisition", dialer.HandshakeTimeout)
	}
	dialer.TLSClientConfig = upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport := make(chan *deadlineRecordingConn, 1)
	dialDeadline := make(chan bool, 1)
	dialer.NetDialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
		_, hasDeadline := dialCtx.Deadline()
		dialDeadline <- hasDeadline
		conn, errDial := (&net.Dialer{}).DialContext(dialCtx, network, address)
		if errDial != nil {
			return nil, errDial
		}
		recorded := &deadlineRecordingConn{Conn: conn}
		transport <- recorded
		return recorded, nil
	}
	closeDialOnCancel(dialer, ctx)
	done := make(chan error, 1)
	go func() {
		conn, response, errDial := dialer.DialContext(ctx, "wss"+strings.TrimPrefix(upstream.URL, "https"), http.Header{"Authorization": {"Bearer synthetic"}})
		if conn != nil {
			_ = conn.Close()
		}
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		done <- errDial
	}()
	waitLiveEvent(t, arrived, "pending authenticated TLS upgrade")
	if <-dialDeadline {
		t.Error("dial context acquired a network deadline")
	}
	recorded := <-transport
	select {
	case errDial := <-done:
		t.Fatalf("dial ended without cancellation or upstream reply: %v", errDial)
	default:
	}
	cancel()
	waitLiveEvent(t, gone, "pending TLS socket release")
	select {
	case errDial := <-done:
		if errDial == nil {
			t.Fatal("cancelled upgrade succeeded")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dial goroutine not released on context cancel")
	}
	recorded.mu.Lock()
	defer recorded.mu.Unlock()
	for _, deadline := range recorded.deadlines {
		if !deadline.IsZero() {
			t.Errorf("transport received network deadline %v", deadline)
		}
	}
}

// Closing a real downstream TCP connection cancels the HTTP request context.
// Exercise every live dialer caller, not merely a synthetic cancelled context.
func TestPendingLiveUpgradeClientDisconnectReleasesDialAndSocket(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, path := range []string{"/v1/realtime", "/v1/realtime?call_id=call", "/v1/realtime/calls/call", "/v1/live/call"} {
		t.Run(path, func(t *testing.T) {
			arrived, gone, stall := make(chan struct{}), make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic" {
					t.Error("pending upgrade did not use pinned OAuth")
				}
				close(arrived)
				select {
				case <-r.Context().Done():
					close(gone)
				case <-stall:
				}
			}))
			defer upstream.Close()
			manager := auth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(&captureExecutor{})
			registerCredential(t, manager, &auth.Auth{ID: "A", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic"}})
			h := NewHandler(manager, nil)
			defer h.Close()
			h.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http")
			h.sessions.put("call", liveSession{authID: "A", model: defaultLiveModel, ownerPrincipal: "owner", ownerProvider: "config-api-key"})
			released := make(chan struct{})
			router := gin.New()
			next := func(c *gin.Context) {
				c.Set("userApiKey", "owner")
				c.Set("accessProvider", "config-api-key")
				if strings.HasPrefix(path, "/v1/realtime?") || path == "/v1/realtime" {
					h.HandleRealtimeWebsocket(c)
				} else {
					h.HandleSideband(c)
				}
				close(released) // Includes releaseRaw and the synchronous DialContext return.
			}
			router.GET("/v1/realtime", next)
			router.GET("/v1/realtime/calls/:call_id", next)
			router.GET("/v1/live/:call_id", next)
			server := httptest.NewServer(router)
			defer server.Close()
			defer close(stall) // Unblock a broken implementation before server shutdown.
			conn, errDial := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if errDial != nil {
				t.Fatal(errDial)
			}
			defer conn.Close()
			_, errWrite := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: c3ludGhldGljLWtleS0xMg==\r\n\r\n", path)
			if errWrite != nil {
				t.Fatal(errWrite)
			}
			waitLiveEvent(t, arrived, "authenticated upstream upgrade")
			if errClose := conn.Close(); errClose != nil {
				t.Fatal(errClose)
			}
			waitLiveEvent(t, gone, "client disconnect closing upstream socket")
			waitLiveEvent(t, released, "client disconnect releasing dial goroutine and relay")
			h.mediaRelayMu.Lock()
			n := len(h.rawRelayOwners)
			h.mediaRelayMu.Unlock()
			if n != 0 {
				t.Fatalf("client disconnect left %d raw relay owners", n)
			}
		})
	}
}
