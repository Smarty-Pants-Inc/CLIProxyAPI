package live

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func livePolicyConfig() *config.Config {
	digest := sha256.Sum256([]byte("owner"))
	return &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"owner"}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:])}}}, WebsocketAuth: true}
}

func TestKeyPolicyActivationClosesRawRelays(t *testing.T) {
	for _, mode := range []string{"direct", "sideband", "pending initialization"} {
		t.Run(mode, func(t *testing.T) {
			arrived, proceed := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(arrived)
				if mode == "pending initialization" {
					<-proceed
				}
				conn, err := sidebandUpgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				_ = conn.WriteMessage(websocket.TextMessage, []byte("ready"))
				for {
					kind, body, err := conn.ReadMessage()
					if err != nil {
						return
					}
					_ = conn.WriteMessage(kind, body)
				}
			}))
			defer upstream.Close()
			m := auth.NewManager(nil, nil, nil)
			m.RegisterExecutor(&captureExecutor{})
			registerCredential(t, m, &auth.Auth{ID: "A", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic"}})
			h := NewHandler(m, nil)
			defer h.Close()
			h.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http")
			h.sessions.put("call", liveSession{authID: "A", model: defaultLiveModel, ownerPrincipal: "owner", ownerProvider: "config-api-key"})
			router := gin.New()
			router.GET("/v1/realtime", func(c *gin.Context) {
				c.Set("userApiKey", "owner")
				c.Set("accessProvider", "config-api-key")
				if mode == "pending initialization" {
					c.Set(ClientSecretSessionContextKey, json.RawMessage(`{"model":"gpt-live-1-codex","instructions":"synthetic"}`))
				}
				h.HandleRealtimeWebsocket(c)
			})
			server := httptest.NewServer(router)
			defer server.Close()
			url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/realtime"
			if mode == "sideband" {
				url += "?call_id=call"
			}
			if mode == "pending initialization" {
				result := make(chan error, 1)
				go func() {
					conn, response, err := websocket.DefaultDialer.Dial(url, nil)
					if conn != nil {
						conn.Close()
					}
					if response != nil {
						response.Body.Close()
					}
					result <- err
				}()
				<-arrived
				if err := h.UpdateConfig(livePolicyConfig()); err != nil {
					t.Fatal(err)
				}
				close(proceed)
				if err := <-result; err == nil {
					t.Fatal("policy activation allowed pending initialization")
				}
				return
			}
			conn, _, err := websocket.DefaultDialer.Dial(url, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, _, err := conn.ReadMessage(); err != nil {
				t.Fatal(err)
			}
			_ = conn.WriteMessage(websocket.TextMessage, []byte("before"))
			if _, _, err := conn.ReadMessage(); err != nil {
				t.Fatal(err)
			}
			if err := h.UpdateConfig(livePolicyConfig()); err != nil {
				t.Fatal(err)
			}
			_ = conn.WriteMessage(websocket.TextMessage, []byte("after"))
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, body, err := conn.ReadMessage(); err == nil {
				t.Fatalf("post-policy frame relayed: %q", body)
			}
		})
	}
}

func TestKeyPolicyOwnerHangupIsLocal(t *testing.T) {
	for _, owner := range []string{"other", "owner"} {
		m := auth.NewManager(nil, nil, nil)
		m.SetConfig(livePolicyConfig())
		h := NewHandler(m, livePolicyConfig())
		defer h.Close()
		closed := false
		resources := &liveSessionResources{}
		resources.add(func() error { closed = true; return nil })
		h.sessions.put("call", liveSession{ownerPrincipal: "owner", ownerProvider: "config-api-key", resources: resources})
		rr := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rr)
		c.Request = httptest.NewRequest("POST", "/v1/realtime/calls/call/hangup", strings.NewReader(`{"arbitrary":"must not forward"}`))
		c.Params = gin.Params{{Key: "call_id", Value: "call"}}
		c.Set("userApiKey", owner)
		c.Set("accessProvider", "config-api-key")
		h.HandleHangup(c)
		c.Writer.WriteHeaderNow()
		if owner == "owner" && (!closed || rr.Code != 204) {
			t.Fatalf("owner cleanup: closed=%t status=%d", closed, rr.Code)
		}
		if owner == "other" && (closed || rr.Code != 403) {
			t.Fatalf("foreign cleanup: closed=%t status=%d", closed, rr.Code)
		}
	}
}
