package live

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
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

func TestAPIKeyPolicyDirectMediaRequiresEnforcingRelay(t *testing.T) {
	const key = "synthetic-direct-media-client"
	digest := sha256.Sum256([]byte(key))
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}}}})
	handler := NewHandler(manager, nil)
	router := gin.New()
	router.POST("/v1/realtime/calls", handler.Handle)
	request := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls?model=gpt-realtime", strings.NewReader("v=0\r\n"))
	request.Header.Set("Content-Type", "application/sdp")
	request = request.WithContext(auth.WithClientAPIKey(context.Background(), key))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "enforcing WebRTC media relay") {
		t.Fatalf("direct media escaped policy: %d %s", response.Code, response.Body.String())
	}
}

func TestAPIKeyPolicyFragmentedRelayRechecksEveryChunk(t *testing.T) {
	const key = "synthetic-fragment-policy-client"
	digest := sha256.Sum256([]byte(key))
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified@example.com"}}}}}
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{ID: "fragment-policy-auth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"email": "verified@example.com", "access_token": "synthetic-token"}})
	accepted := make(chan struct{})
	remaining := make(chan []byte, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"session.created"}`))
		_, reader, err := connection.NextReader()
		if err != nil {
			t.Error(err)
			return
		}
		first := make([]byte, 4096)
		if _, err := io.ReadFull(reader, first); err != nil {
			t.Error(err)
			return
		}
		close(accepted)
		tail, _ := io.ReadAll(reader)
		remaining <- tail
	}))
	defer upstream.Close()
	handler := NewHandler(manager, nil)
	handler.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	router := gin.New()
	router.GET("/v1/realtime", func(c *gin.Context) {
		c.Request = c.Request.WithContext(auth.WithClientAPIKeyPolicies(c.Request.Context(), key, cfg.APIKeyPolicies))
	}, handler.HandleRealtimeWebsocket)
	downstream := httptest.NewServer(router)
	defer downstream.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	writer, err := connection.NextWriter(websocket.TextMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("a"), 128<<10)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("initial permitted fragment was not forwarded")
	}
	revoked := cfg.CloneForRuntime()
	revoked.APIKeyPolicies[0].AllowedAuths = nil
	manager.SetConfig(revoked)
	writer.Write([]byte("REVOKED-CLIENT-CONTENT"))
	writer.Close()
	connection.ReadMessage()
	select {
	case tail := <-remaining:
		if bytes.Contains(tail, []byte("REVOKED-CLIENT-CONTENT")) {
			t.Fatal("continuation fragment bypassed policy")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked fragmented relay not closed")
	}
}

func TestAPIKeyPolicyRealtimeRelayRevocationDoesNotForward(t *testing.T) {
	const key = "synthetic-realtime-policy-client"
	digest := sha256.Sum256([]byte(key))
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified@example.com"}}}}}
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{ID: "realtime-policy-auth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"email": "verified@example.com", "access_token": "synthetic-token"}})
	var frames atomic.Int32
	done := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = connection.Close() }()
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"session.created"}`))
		if _, _, err := connection.ReadMessage(); err == nil {
			frames.Add(1)
		}
	}))
	defer upstream.Close()
	handler := NewHandler(manager, nil)
	handler.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	router := gin.New()
	router.GET("/v1/realtime", func(c *gin.Context) {
		c.Request = c.Request.WithContext(auth.WithClientAPIKey(c.Request.Context(), key))
		c.Next()
	}, handler.HandleRealtimeWebsocket)
	downstream := httptest.NewServer(router)
	defer downstream.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	revoked := cfg.CloneForRuntime()
	revoked.APIKeyPolicies[0].AllowedAuths = nil
	manager.SetConfig(revoked)
	if err := connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.create","input":"must not reach upstream"}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("revoked relay stayed open")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked upstream relay not closed")
	}
	if frames.Load() != 0 {
		t.Fatalf("revoked credential forwarded %d frames", frames.Load())
	}
}
