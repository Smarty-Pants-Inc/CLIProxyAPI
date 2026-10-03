package cliproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/wsrelay"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// The normal server logs requests concurrently with the socket reader.
type r3LiveReloadLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *r3LiveReloadLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *r3LiveReloadLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestR3CombinedLiveRelayPolicyReload(t *testing.T) {
	ctx := context.Background()
	key := "r3-existing-live-client-secret"
	digest := sha256.Sum256([]byte(key))
	policy := config.APIKeyPolicy{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"A"}}
	cfg, errParse := config.ParseConfigBytes([]byte("{}"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	cfg.APIKeys = []string{key}
	cfg.WebsocketAuth = true
	cfg.CommercialMode = true
	cfg.AuthDir = t.TempDir()
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	// Build the real API server, with the same exported relay attachment used by Service.Run.
	newServer := func(c *config.Config) (*Service, *wsrelay.Manager, *httptest.Server, <-chan string, *atomic.Int32, *atomic.Int32) {
		m := coreauth.NewManager(nil, nil, nil)
		access := sdkaccess.NewManager()
		server := api.NewServer(c, m, access, configPath)
		connected := make(chan string, 1)
		handled := &atomic.Int32{}
		created := &atomic.Int32{}
		relay := wsrelay.NewManager(wsrelay.Options{
			ProviderFactory: func(*http.Request) (string, error) {
				created.Add(1)
				return "r3-live-provider", nil
			},
			OnConnected: func(provider string) { connected <- provider },
		})
		server.AttachWebsocketRoute(relay.Path(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled.Add(1)
			relay.Handler().ServeHTTP(w, r)
		}))
		httpServer := httptest.NewServer(server.Handler())
		t.Cleanup(func() {
			if errStop := relay.Stop(ctx); errStop != nil {
				t.Errorf("stop relay: %v", errStop)
			}
			httpServer.Close()
		})
		return &Service{cfg: c, coreManager: m, accessManager: access, server: server, wsGateway: relay}, relay, httpServer, connected, handled, created
	}
	metadata := func(s *Service, clientKey string, wantPolicy bool) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/ws", nil)
		r.Header.Set("Authorization", "Bearer "+clientKey)
		result, errAuth := s.accessManager.Authenticate(ctx, r)
		if errAuth != nil || result == nil {
			t.Fatalf("authenticate access metadata: %v", errAuth)
		}
		if result.Principal != clientKey || (result.Metadata["key_policy"] != "") != wantPolicy {
			t.Errorf("access metadata policy=%t, want %t", result.Metadata["key_policy"] != "", wantPolicy)
		}
	}
	refused := func(baseURL, clientKey string, status int) {
		t.Helper()
		headers := http.Header{"Authorization": []string{"Bearer " + clientKey}}
		conn, response, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(baseURL, "http")+"/v1/ws", headers)
		if conn != nil {
			if errClose := conn.Close(); errClose != nil {
				t.Errorf("close unexpected socket: %v", errClose)
			}
		}
		if response == nil {
			t.Fatalf("refused upgrade missing response: %v", errDial)
		}
		body, errRead := io.ReadAll(response.Body)
		if errClose := response.Body.Close(); errClose != nil {
			t.Errorf("close refusal body: %v", errClose)
		}
		if errRead != nil || errDial == nil || response.StatusCode != status {
			t.Fatalf("upgrade status=%d, want=%d, dial=%v read=%v body=%s", response.StatusCode, status, errDial, errRead, body)
		}
		if status == http.StatusServiceUnavailable && !strings.Contains(string(body), "api_key_policy_unavailable") {
			t.Errorf("missing fixed policy refusal: %s", body)
		}
	}

	s, relay, httpServer, connected, handled, created := newServer(cfg)
	refused(httpServer.URL, "invalid-client", http.StatusUnauthorized)
	if handled.Load() != 0 || created.Load() != 0 {
		t.Fatal("unauthenticated upgrade reached relay")
	}
	metadata(s, key, false)
	conn, response, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(httpServer.URL, "http")+"/v1/ws", http.Header{"Authorization": []string{"Bearer " + key}})
	if errDial != nil {
		t.Fatalf("authenticated live upgrade: %v (response=%v)", errDial, response)
	}
	t.Cleanup(func() {
		if errClose := conn.Close(); errClose != nil {
			t.Errorf("close live socket: %v", errClose)
		}
	})
	provider := <-connected
	if handled.Load() != 1 || created.Load() != 1 {
		t.Fatal("live upgrade did not create exactly one relay resource")
	}
	// No test-specific established-network deadlines: the harness -timeout bounds failures.
	exchange := func(id string) {
		t.Helper()
		replies, errSend := relay.Send(ctx, provider, wsrelay.Message{ID: id, Type: wsrelay.MessageTypeHTTPReq, Payload: map[string]any{"body": id}})
		if errSend != nil {
			t.Fatalf("send on established relay: %v", errSend)
		}
		var frame wsrelay.Message
		if errRead := conn.ReadJSON(&frame); errRead != nil {
			t.Fatalf("read actual relay frame: %v", errRead)
		}
		if frame.ID != id || frame.Type != wsrelay.MessageTypeHTTPReq || frame.Payload["body"] != id {
			t.Fatalf("unexpected request frame: %+v", frame)
		}
		if errWrite := conn.WriteJSON(wsrelay.Message{ID: frame.ID, Type: wsrelay.MessageTypeHTTPResp, Payload: map[string]any{"body": "echo-" + id}}); errWrite != nil {
			t.Fatalf("write actual reply frame: %v", errWrite)
		}
		reply, ok := <-replies
		if !ok || reply.ID != id || reply.Type != wsrelay.MessageTypeHTTPResp || reply.Payload["body"] != "echo-"+id {
			t.Fatalf("actual relay response missing: %+v, open=%t", reply, ok)
		}
	}
	exchange("before-reload")

	requested := cfg.CloneForRuntime()
	requested.APIKeyPolicies = []config.APIKeyPolicy{policy}
	requested.PassthroughHeaders = true // An unrelated per-server setting must still publish.
	disk, errMarshal := yaml.Marshal(requested)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if errWrite := os.WriteFile(configPath, disk, 0600); errWrite != nil {
		t.Fatal(errWrite)
	}
	var warnings r3LiveReloadLog
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&warnings)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	failures := 0
	s.updateServerClientsContextFn = func(_ context.Context, effective *config.Config) bool {
		failures++
		// This seam runs after applyManagerConfig, not before security publication.
		if len(s.coreManager.KeyPolicies(key)) != 0 || len(effective.APIKeyPolicies) != 0 {
			t.Error("policy hot-activated before unrelated server-client runtime failure")
		}
		return false
	}
	for range 2 {
		if s.applyConfigUpdateWithAuthSynthesis(ctx, requested, true) {
			t.Error("injected runtime failure unexpectedly succeeded")
		}
	}
	if failures != 2 {
		t.Fatalf("post-publication failure seam reached %d times, want 2", failures)
	}
	if len(s.cfg.APIKeyPolicies) != 0 || len(s.coreManager.KeyPolicies(key)) != 0 {
		t.Error("partial reload changed Service/core-manager unpolicied state")
	}
	if !s.cfg.PassthroughHeaders {
		t.Error("unrelated runtime setting was lost")
	}
	metadata(s, key, false)
	warning := "client-key policy change for " + policy.KeySHA256 + " takes effect on restart"
	if strings.Count(warnings.String(), warning) != 1 || strings.Contains(warnings.String(), key) {
		t.Errorf("expected one fixed digest-only warning, got %q", warnings.String())
	}
	exchange("after-failed-reload")

	// A genuinely new key has no previous session state and can be restricted on reload.
	newKey := "r3-new-restricted-client-secret"
	newDigest := sha256.Sum256([]byte(newKey))
	next := requested.CloneForRuntime()
	next.APIKeys = append(next.APIKeys, newKey)
	next.APIKeyPolicies = append(next.APIKeyPolicies, config.APIKeyPolicy{KeySHA256: hex.EncodeToString(newDigest[:]), AllowedAuths: []string{"A"}})
	s.updateServerClientsContextFn = nil
	if !s.applyConfigUpdateWithAuthSynthesis(ctx, next, false) {
		t.Fatal("new policied key reload failed")
	}
	if len(s.coreManager.KeyPolicies(newKey)) != 1 || len(s.coreManager.KeyPolicies(key)) != 0 {
		t.Error("new-key reload did not preserve old-key/new-key policy distinction")
	}
	metadata(s, key, false)
	metadata(s, newKey, true)
	refused(httpServer.URL, newKey, http.StatusServiceUnavailable)
	if handled.Load() != 1 || created.Load() != 1 {
		t.Error("new restricted key created a relay resource")
	}
	exchange("after-new-key-reload")
	if strings.Count(warnings.String(), warning) != 1 {
		t.Error("later successful publication repeated the restart warning")
	}

	// Reconstruct fresh process-lifetime Server/Manager state from the requested disk config,
	// not the effective (frozen) Service snapshot. This is not provider media revocation proof.
	freshCfg, errLoad := config.LoadConfig(configPath)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	fresh, freshRelay, freshHTTP, freshConnected, freshHandled, freshCreated := newServer(freshCfg)
	if len(fresh.coreManager.KeyPolicies(key)) != 1 {
		t.Fatal("fresh manager did not adopt requested disk policy")
	}
	metadata(fresh, key, true)
	refused(freshHTTP.URL, key, http.StatusServiceUnavailable)
	if freshHandled.Load() != 0 || freshCreated.Load() != 0 {
		t.Error("fresh restricted upgrade reached handler/resource creation")
	}
	select {
	case <-freshConnected:
		t.Error("fresh restricted upgrade invoked onConnected")
	default:
	}
	if _, errSend := freshRelay.Send(ctx, "r3-live-provider", wsrelay.Message{ID: "must-not-exist", Type: wsrelay.MessageTypeHTTPReq}); errSend == nil {
		t.Error("fresh restricted upgrade left a usable relay session")
	}
}
