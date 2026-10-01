package live

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
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
	for _, cap := range []*int64{nil, func() *int64 { n := int64(100); return &n }()} {
		manager, cfg := controlsLiveManager(t, cap)
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
			if cap != nil && model == "gpt-realtime" && !strings.Contains(response.Body.String(), "requires recorded usage") {
				t.Fatal("unmetered path didn't reject capped key")
			}
		}
	}
}

func TestAPIKeyPolicyRealtimeFragmentedModelChangeNeverForwards(t *testing.T) {
	manager, cfg := controlsLiveManager(t, nil)
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{ID: "model-control-auth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"email": "verified@example.com", "access_token": "synthetic-token"}})
	var frames atomic.Int32
	done := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"session.created"}`))
		if _, _, err := conn.ReadMessage(); err == nil {
			frames.Add(1)
		}
	}))
	defer upstream.Close()
	handler := NewHandler(manager, nil)
	handler.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	router := gin.New()
	router.GET("/v1/realtime", func(c *gin.Context) {
		c.Request = c.Request.WithContext(auth.WithClientAPIKeyPolicies(c.Request.Context(), "synthetic-live-controls", cfg.APIKeyPolicies))
	}, handler.HandleRealtimeWebsocket)
	downstream := httptest.NewServer(router)
	defer downstream.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	writer, err := conn.NextWriter(websocket.TextMessage)
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte(`{"type":"session.update","session":{"model":"forbidden-model","instructions":"` + strings.Repeat("private-client-content", 1000)))
	writer.Write([]byte(`"}}`))
	writer.Close()
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("forbidden model change relay stayed open")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("forbidden relay did not close")
	}
	if frames.Load() != 0 {
		t.Fatal("fragmented denied model payload reached upstream")
	}
}
