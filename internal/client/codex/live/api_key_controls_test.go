package live

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func controlsLiveManager(t *testing.T, cap *int64) (*auth.Manager, *config.Config) {
	t.Helper()
	digest := sha256.Sum256([]byte("synthetic-live-controls"))
	models := []string{"gpt-realtime"}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"*"}, AllowedModels: &models, DailyTokenCap: cap}}}}
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	return manager, cfg
}

func TestAPIKeyPolicyRealtimeModelsAndUnmeteredCapFailClosed(t *testing.T) {
	for _, kind := range []string{"none", "token", "request"} {
		cap := int64(100)
		manager, cfg := controlsLiveManager(t, nil)
		if kind == "token" {
			cfg.APIKeyPolicies[0].DailyTokenCap = &cap
		} else if kind == "request" {
			cfg.APIKeyPolicies[0].DailyRequestCap = &cap
		}
		manager.SetConfig(cfg)
		handler := NewHandler(manager, nil)
		router := gin.New()
		router.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(auth.WithClientAPIKeyPolicies(c.Request.Context(), "synthetic-live-controls", cfg.APIKeyPolicies))
		})
		router.POST("/v1/realtime/client_secrets", handler.CreateClientSecret)
		router.GET("/v1/realtime", handler.HandleDirectWebsocket)
		for _, model := range []string{"forbidden-model", "gpt-realtime"} {
			mint := httptest.NewRequest(http.MethodPost, "/v1/realtime/client_secrets", strings.NewReader(`{"session":{"type":"realtime","model":"`+model+`"}}`))
			response := httptest.NewRecorder()
			router.ServeHTTP(response, mint)
			want := http.StatusOK
			if model == "forbidden-model" {
				want = 403
			}
			if response.Code != want {
				t.Fatalf("mint model=%s status=%d body=%s", model, response.Code, response.Body.String())
			}
			request := httptest.NewRequest(http.MethodGet, "/v1/realtime?model="+model, nil)
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Upgrade", "websocket")
			response = httptest.NewRecorder()
			router.ServeHTTP(response, request)
			want = 503
			if model == "forbidden-model" {
				want = 403
			}
			if response.Code != want {
				t.Fatalf("direct model=%s status=%d body=%s", model, response.Code, response.Body.String())
			}
			if model == "gpt-realtime" && !strings.Contains(response.Body.String(), "unavailable for client keys with policies") {
				t.Fatal("direct path did not reject policied key")
			}
		}
	}
}

func TestAPIKeyPolicyRealtimeFragmentedModelChangeNeverForwards(t *testing.T) {
	manager, cfg := controlsLiveManager(t, nil)
	assertPolicyWebsocketDenied(t, manager, cfg, "synthetic-live-controls", true, false)
}
