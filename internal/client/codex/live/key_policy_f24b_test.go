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

// F24B first-policy trigger: with no policies yet and no media relay, an
// unpolicied key must not open a provider-direct call that a later first policy
// and restart could not end. The refusal comes before selection, dial or storage.
func TestF24BPassthroughRefusedWithoutPolicies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := auth.NewManager(nil, nil, nil)
	executor := &captureExecutor{responseBody: &trackedResponseBody{Reader: strings.NewReader("v=0\r\no=upstream-answer\r\n")}}
	manager.RegisterExecutor(executor)
	registerCredential(t, manager, &auth.Auth{ID: "codex-oauth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "oauth-token"}})
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"K"}}, WebsocketAuth: true}
	manager.SetConfig(cfg)
	handler := NewHandler(manager, cfg)
	defer handler.Close()
	router := gin.New()
	router.POST("/v1/realtime/calls", func(c *gin.Context) { c.Set("userApiKey", "K"); handler.Handle(c) })
	req := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls", strings.NewReader(multipartBody("b", "v=0\r\no=client-offer\r\n", `{"model":"gpt-live-1-codex"}`)))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "api_key_policy_requires_media_relay") {
		t.Fatalf("passthrough without policies: status=%d body=%s, want 503 api_key_policy_requires_media_relay", rr.Code, rr.Body.String())
	}
	if executor.body != nil || len(handler.rawRelayOwners) != 0 || len(handler.sessions.sessions) != 0 {
		t.Fatal("refused passthrough dialed upstream or kept resources")
	}
}
