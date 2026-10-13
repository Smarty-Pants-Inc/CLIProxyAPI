package live

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// F24B cut: while any client-key policy exists, an unpolicied key may not open an
// SDP-passthrough call (provider-direct media that restart cannot end). Calls on
// the gateway-owned media relay are still accepted and end on shutdown.
func TestR5PoliciesRequireGatewayMediaRelay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, relayed := range []bool{false, true} {
		name := "passthrough"
		if relayed {
			name = "relayed"
		}
		t.Run(name, func(t *testing.T) {
			manager := auth.NewManager(nil, nil, nil)
			executor := &captureExecutor{responseBody: &trackedResponseBody{Reader: strings.NewReader("v=0\r\no=upstream-answer\r\n")}}
			manager.RegisterExecutor(executor)
			registerCredential(t, manager, &auth.Auth{ID: "codex-oauth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "oauth-token"}})
			cfg := &config.Config{SDKConfig: config.SDKConfig{
				APIKeys:        []string{"owner", "member"},
				APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: config.APIKeyDigest("member")}},
			}, WebsocketAuth: true}
			manager.SetConfig(cfg)
			handler := NewHandler(manager, cfg)
			media := &fakeMediaSession{downstreamSDP: "v=0\r\no=downstream-answer\r\n"}
			if relayed {
				handler.mediaRelay = &fakeMediaRelay{upstreamOffer: "v=0\r\no=gateway-offer\r\n", session: media}
			}
			router := gin.New()
			router.POST("/v1/realtime/calls", func(c *gin.Context) { c.Set("userApiKey", "owner"); handler.Handle(c) })
			req := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls", strings.NewReader(multipartBody("b", "v=0\r\no=client-offer\r\n", `{"model":"gpt-live-1-codex"}`)))
			req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
			if !relayed {
				if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "api_key_policy_requires_media_relay") {
					t.Fatalf("passthrough with policies: status=%d body=%s, want 503 api_key_policy_requires_media_relay", rr.Code, rr.Body.String())
				}
				if executor.body != nil || len(handler.rawRelayOwners) != 0 || len(handler.sessions.sessions) != 0 {
					t.Fatal("refused passthrough dialed upstream or kept resources")
				}
				return
			}
			if rr.Code != http.StatusCreated {
				t.Fatalf("relayed call: status=%d body=%s", rr.Code, rr.Body.String())
			}
			handler.Close()
			if !media.closed.Load() || media.closeReason != "server_stopped" {
				t.Fatalf("relayed call not ended on shutdown: closed=%t reason=%q", media.closed.Load(), media.closeReason)
			}
		})
	}
}

// F28: owner hangup during a join whose upstream handshake is stalled must cancel
// the pending attempt promptly, not when the upstream eventually answers.
func TestR5OwnerHangupCancelsPendingSidebandJoin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	arrived, upstreamGone, stall := make(chan struct{}), make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(arrived)
		select {
		case <-r.Context().Done():
			close(upstreamGone)
		case <-stall:
		}
	}))
	defer upstream.Close()
	m := auth.NewManager(nil, nil, nil)
	m.RegisterExecutor(&captureExecutor{statusCode: http.StatusOK, responseBody: &trackedResponseBody{Reader: strings.NewReader("{}")}})
	registerCredential(t, m, &auth.Auth{ID: "A", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic"}})
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"owner", "other"}}, WebsocketAuth: true}
	m.SetConfig(cfg)
	h := NewHandler(m, cfg)
	defer h.Close()
	h.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http")
	h.sessions.put("call", liveSession{authID: "A", model: defaultLiveModel, ownerPrincipal: "owner", ownerProvider: "config-api-key"})
	as := func(key string, next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("userApiKey", key)
			c.Set("accessProvider", "config-api-key")
			next(c)
		}
	}
	relayReleased, hangupProcessed := make(chan struct{}), make(chan string, 2)
	router := gin.New()
	router.GET("/v1/realtime/calls/:call_id", func(c *gin.Context) {
		as("owner", h.HandleSideband)(c)
		close(relayReleased) // HandleSideband has run its releaseRaw defer.
	})
	router.POST("/v1/realtime/calls/:call_id/hangup", func(c *gin.Context) {
		key := c.GetHeader("X-Key")
		as(key, h.HandleHangup)(c)
		hangupProcessed <- key
	})
	server := httptest.NewServer(router)
	defer server.Close()
	defer close(stall) // Unblock a broken implementation before server shutdown.

	joined := make(chan error, 1)
	go func() {
		conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime/calls/call", nil)
		if conn != nil {
			_ = conn.Close()
		}
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		joined <- err
	}()
	waitLiveEvent(t, arrived, "authenticated upgrade arrival")
	h.mediaRelayMu.Lock()
	var pending *liveSessionResources
	for resources := range h.rawRelayOwners {
		pending = resources
	}
	h.mediaRelayMu.Unlock()
	if pending == nil {
		t.Fatal("join was not attached before dial")
	}

	hangup := func(key string) int {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/realtime/calls/call/hangup", nil)
		req.Header.Set("X-Key", key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		select {
		case processed := <-hangupProcessed:
			if processed != key {
				t.Fatalf("processed hangup %q, want %q", processed, key)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("hangup handler did not finish")
		}
		return resp.StatusCode
	}
	if code := hangup("other"); code != http.StatusForbidden {
		t.Fatalf("foreign hangup status=%d, want 403", code)
	}
	// The foreign handler has fully returned. Cancellation closes resources
	// synchronously; do not infer non-cancellation from an arbitrary delay.
	pending.mu.Lock()
	closed := pending.closed
	pending.mu.Unlock()
	if closed {
		t.Fatal("foreign hangup closed the owner's pending transport")
	}
	select {
	case <-upstreamGone:
		t.Fatal("foreign hangup cancelled the owner's join")
	default:
	}
	if code := hangup("owner"); code != http.StatusOK {
		t.Fatalf("owner hangup status=%d", code)
	}
	waitLiveEvent(t, upstreamGone, "owner hangup closing pending upstream handshake")
	select {
	case err := <-joined:
		if err == nil {
			t.Fatal("join succeeded after owner hangup")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("joining request still pending after owner hangup")
	}
	if _, ok := h.sessions.peek("call"); ok {
		t.Fatal("call still stored after owner hangup")
	}
	waitLiveEvent(t, relayReleased, "raw relay cleanup")
	h.mediaRelayMu.Lock()
	n := len(h.rawRelayOwners)
	h.mediaRelayMu.Unlock()
	if n != 0 {
		t.Fatalf("raw relay owners left: %d", n)
	}
}
