package live

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

// Exercise the real generated session.update path. A large message exceeds the
// loopback socket buffers: the peer activates a denying policy after reading its
// first byte, before draining the rest. The connection starts unpolicied because
// policy-bound direct Realtime is now denied before dialing. An unchecked
// WriteMessage completes; checked writes abort.
func TestRound2DirectInitializationRevocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const key = "synthetic-init-key"
	digest := sha256.Sum256([]byte(key))
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{
		KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"original@example.com"},
	}}}}
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(&config.Config{})
	manager.RegisterExecutor(&captureExecutor{})
	registerCredential(t, manager, &auth.Auth{ID: "init-auth", Provider: "codex", Status: auth.StatusActive,
		Metadata: map[string]any{"access_token": "synthetic-token", "email": "original@example.com"}})
	type receipt struct {
		bytes int64
		err   error
	}
	received := make(chan receipt, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			received <- receipt{err: err}
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, reader, err := conn.NextReader()
		if err != nil {
			received <- receipt{err: err}
			return
		}
		var first [1]byte
		if _, err = io.ReadFull(reader, first[:]); err != nil {
			received <- receipt{err: err}
			return
		}
		revoked := cfg.CloneForRuntime()
		revoked.APIKeyPolicies[0].AllowedAuths = nil
		manager.SetConfig(revoked)
		n, err := io.Copy(io.Discard, reader)
		received <- receipt{bytes: n + 1, err: err}
	}))
	defer upstream.Close()
	handler := NewHandler(manager, cfg)
	handler.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
	session, err := json.Marshal(map[string]string{"type": "realtime", "model": "gpt-live-1-codex", "instructions": strings.Repeat("i", 16<<20)})
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/v1/realtime", func(c *gin.Context) {
		c.Set(ClientSecretSessionContextKey, json.RawMessage(session))
		c.Set(ClientSecretPrincipalContextKey, "synthetic-session")
		c.Request = c.Request.WithContext(auth.WithClientAPIKeyPolicies(c.Request.Context(), key, nil))
	}, handler.HandleDirectWebsocket)
	request := httptest.NewRequest(http.MethodGet, "/v1/realtime?model=gpt-realtime", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	// The handler must reject before attempting the downstream upgrade.
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	select {
	case got := <-received:
		if got.bytes == 0 {
			t.Fatalf("initialization never reached upstream: %v; response=%s", got.err, response.Body.String())
		}
		if got.err == nil || !strings.Contains(got.err.Error(), "unexpected EOF") || got.bytes >= 16<<20 {
			t.Fatalf("generated session.update completed after revocation: %d bytes, err=%v", got.bytes, got.err)
		}
		if response.Code != http.StatusBadGateway {
			t.Fatalf("status=%d, want 502: %s", response.Code, response.Body.String())
		}
		t.Logf("revoked generated update aborted after %d bytes: %v", got.bytes, got.err)
	case <-time.After(16 * time.Second):
		t.Fatal("initialization receiver did not finish")
	}
}
