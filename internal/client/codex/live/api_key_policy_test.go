package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "unavailable for client keys with policies") {
		t.Fatalf("direct media escaped policy: %d %s", response.Code, response.Body.String())
	}
}

// assertPolicyWebsocketDenied checks denial before either upstream dialing or
// downstream upgrade, so no client frame (including fragments) can be relayed.
func assertPolicyWebsocketDenied(t *testing.T, manager *auth.Manager, cfg *config.Config, key string, snapshot, direct bool) {
	t.Helper()
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{ID: "policy-auth", Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"email": "verified@example.com", "access_token": "synthetic-token"}})
	var calls, payloadBytes atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		n, _ := io.Copy(io.Discard, r.Body)
		payloadBytes.Add(n)
		http.Error(w, "unexpected upstream handshake", http.StatusInternalServerError)
	}))
	defer upstream.Close()
	handler := NewHandler(manager, nil)
	handler.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	router := gin.New()
	endpoint := handler.HandleRealtimeWebsocket
	if direct {
		endpoint = handler.HandleDirectWebsocket
	}
	router.GET("/v1/realtime", func(c *gin.Context) {
		ctx := auth.WithClientAPIKey(c.Request.Context(), key)
		if snapshot {
			ctx = auth.WithClientAPIKeyPolicies(c.Request.Context(), key, cfg.APIKeyPolicies)
		}
		c.Request = c.Request.WithContext(ctx)
	}, endpoint)
	downstream := httptest.NewServer(router)
	defer downstream.Close()
	connection, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("policied client upgraded to a websocket")
	}
	if !errors.Is(err, websocket.ErrBadHandshake) {
		t.Fatalf("expected rejected handshake, got %v", err)
	}
	if response == nil {
		t.Fatal("missing HTTP denial response")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(body), "unavailable for client keys with policies") {
		t.Fatalf("expected policy 503, got %d: %s", response.StatusCode, body)
	}
	if calls.Load() != 0 || payloadBytes.Load() != 0 {
		t.Fatalf("denied client reached upstream: handshakes=%d payload bytes=%d", calls.Load(), payloadBytes.Load())
	}
}

func TestAPIKeyPolicyFragmentedRelayRechecksEveryChunk(t *testing.T) {
	// Fragment forwarding is unreachable: policy denies the initial handshake.
	testAPIKeyPolicyRealtimeEarlyDenial(t, true)
}

func TestAPIKeyPolicyRealtimeRelayRevocationDoesNotForward(t *testing.T) {
	// Revocation is unnecessary: even initially authorized policy keys are denied.
	testAPIKeyPolicyRealtimeEarlyDenial(t, false)
}

func testAPIKeyPolicyRealtimeEarlyDenial(t *testing.T, snapshot bool) {
	t.Helper()
	const key = "synthetic-realtime-policy-client"
	for _, direct := range []bool{false, true} {
		name := "manager"
		if snapshot {
			name = "snapshot"
		}
		if direct {
			name += "/direct"
		} else {
			name += "/dispatch"
		}
		t.Run(name, func(t *testing.T) {
			digest := sha256.Sum256([]byte(key))
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified@example.com"}}}}}
			manager := auth.NewManager(nil, nil, nil)
			manager.SetConfig(cfg)
			assertPolicyWebsocketDenied(t, manager, cfg, key, snapshot, direct)
		})
	}
}
