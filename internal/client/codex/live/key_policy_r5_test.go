package live

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
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
