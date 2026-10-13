package live

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestR3LiveDirectEntryRefusesBeforeResources(t *testing.T) {
	for _, entry := range []string{"WebRTC", "realtime", "direct websocket", "sideband", "client secret", "legacy session", "translation", "transcription", "SIP", "hangup"} {
		t.Run(entry, func(t *testing.T) {
			cfg := livePolicyConfig()
			m := auth.NewManager(nil, nil, nil)
			m.SetConfig(cfg)
			executor := &captureExecutor{}
			m.RegisterExecutor(executor)
			h := NewHandler(m, cfg)
			defer h.Close()
			resources := &liveSessionResources{}
			closed := false
			resources.add(func() error { closed = true; return nil })
			h.sessions.put("call", liveSession{ownerPrincipal: "owner", ownerProvider: "config-api-key", resources: resources})
			rr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rr)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/realtime/calls/call/hangup", strings.NewReader(`{"model":"gpt-live-1-codex"}`))
			c.Params = gin.Params{{Key: "call_id", Value: "call"}}
			c.Set("userApiKey", "owner")
			c.Set("accessProvider", "config-api-key")
			switch entry {
			case "WebRTC":
				h.Handle(c)
			case "realtime":
				h.HandleRealtimeWebsocket(c)
			case "direct websocket":
				h.HandleDirectWebsocket(c)
			case "sideband":
				h.HandleSideband(c)
			case "client secret":
				h.CreateClientSecret(c)
			case "legacy session":
				h.CreateLegacySession(c)
			case "translation":
				h.HandleTranslation(c)
			case "transcription":
				h.HandleTranscriptionSession(c)
			case "SIP":
				h.HandleSIPControl(c)
			case "hangup":
				h.HandleHangup(c)
			}
			c.Writer.WriteHeaderNow()
			if rr.Code != 503 || !strings.Contains(rr.Body.String(), "api_key_policy_unavailable") {
				t.Errorf("not refused safely: %d %s", rr.Code, rr.Body.String())
			}
			if closed || len(h.clientSecrets.entries) != 0 || len(h.rawRelayOwners) != 0 {
				t.Error("restricted entry touched/created resource")
			}
			stored, ok := h.sessions.sessions["call"]
			if !ok || stored.claimed {
				t.Error("restricted entry claimed/completed call")
			}
			if executor.body != nil {
				t.Error("restricted entry dialed executor")
			}
		})
	}
}
