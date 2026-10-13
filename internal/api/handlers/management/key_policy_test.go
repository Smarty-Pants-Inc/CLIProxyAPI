package management

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestKeyPolicyWSAuthSetterDoesNotMutateInvalidState(t *testing.T) {
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: strings.Repeat("a", 64)}}}, WebsocketAuth: true}
	h := NewHandler(cfg, "must-not-write", nil)
	rr := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rr)
	c.Request = httptest.NewRequest("PUT", "/ws-auth", strings.NewReader(`{"value":false}`))
	h.PutWebsocketAuth(c)
	if rr.Code != 400 || !cfg.WebsocketAuth {
		t.Fatalf("status=%d ws-auth=%t", rr.Code, cfg.WebsocketAuth)
	}
}
