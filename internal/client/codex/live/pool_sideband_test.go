package live

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Trust boundary keep reason: exercise the real pooled handler and WSS relay,
// not just a JSON validator. The hard gateway test separately uses real media.
func TestPoolSidebandRejectsUnknownAndModelSwitchControls(t *testing.T) {
	for _, control := range []struct {
		name string
		kind int
		body string
	}{
		{"model-switch", websocket.TextMessage, `{"type":"session.update","session":{"model":"other"}}`},
		{"unknown", websocket.TextMessage, `{"type":"response.create"}`},
		{"ambiguous-type", websocket.TextMessage, `{"type":"response.create","\u0074ype":"session.close"}`},
		{"binary", websocket.BinaryMessage, `{"type":"session.close"}`},
	} {
		t.Run(control.name, func(t *testing.T) {
			var frames atomic.Int32
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/live/rtc_test" {
					t.Errorf("unexpected upstream path %s", r.URL.Path)
				}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = conn.Close() }()
				for {
					kind, body, errRead := conn.ReadMessage()
					if errRead != nil {
						return
					}
					frames.Add(1)
					if conn.WriteMessage(kind, body) != nil {
						return
					}
				}
			}))
			t.Cleanup(upstream.Close)
			PoolSidebandUpstreamForTest(t, upstream)
			h, manager, _ := newPoolUnitHandler(t, newPoolLiveTestConfig(), echoMediaRelay{}, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
				return poolLiveResponse(), nil
			})
			rr := httptest.NewRecorder()
			servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
			if rr.Code != 201 {
				t.Fatalf("bootstrap %d %s", rr.Code, rr.Body)
			}
			router := gin.New()
			router.GET("/v1/live/:call_id", func(c *gin.Context) {
				c.Set("userApiKey", poolHumanKey)
				c.Set("accessProvider", "config-inline")
				h.HandleSideband(c)
			})
			gateway := httptest.NewServer(router)
			t.Cleanup(gateway.Close)
			conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(gateway.URL, "http")+"/v1/live/rtc_test", nil)
			if err != nil {
				if response != nil {
					_ = response.Body.Close()
				}
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			valid := `{"type":"session.context.append","content":[{"type":"input_text","text":"hello"}]}`
			if err = conn.WriteMessage(websocket.TextMessage, []byte(valid)); err != nil {
				t.Fatal(err)
			}
			_, echoed, err := conn.ReadMessage()
			if err != nil || string(echoed) != valid {
				t.Fatalf("valid control echo %s %v", echoed, err)
			}
			if err = conn.WriteMessage(control.kind, []byte(control.body)); err != nil {
				t.Fatal(err)
			}
			if _, _, err = conn.ReadMessage(); !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
				t.Fatalf("policy close = %v", err)
			}
			h.Close() // join actual copy/dial work and the original call finalizer
			if frames.Load() != 1 {
				t.Fatalf("forbidden control reached provider: frames=%d", frames.Load())
			}
			_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
			if err != nil {
				t.Fatalf("sideband end did not release original slot: %v", err)
			}
			next.Finish()
		})
	}
}
