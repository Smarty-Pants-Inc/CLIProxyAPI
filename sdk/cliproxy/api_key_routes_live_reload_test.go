package cliproxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/wsrelay"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestServiceAPIKeyRoutesLiveReloadWithPluginsEnabled(t *testing.T) {
	ctx := context.Background()
	issuerKey := "  sdk-route-restricted-client-key  "
	restrictedKey := strings.TrimSpace(issuerKey)
	unrestrictedKey := "sdk-route-unrestricted-client-key"

	cfg, errParse := config.ParseConfigBytes([]byte("{}"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	cfg.APIKeys = []string{issuerKey, unrestrictedKey}
	cfg.AuthDir = t.TempDir()
	cfg.CommercialMode = true
	cfg.Plugins.Enabled = true
	cfg.WebsocketAuth = true
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	coreManager := coreauth.NewManager(nil, nil, nil)
	accessManager := sdkaccess.NewManager()
	server := api.NewServer(cfg, coreManager, accessManager, configPath)
	connected := make(chan string, 8)
	var handled atomic.Int32
	var created atomic.Int32
	relay := wsrelay.NewManager(wsrelay.Options{
		ProviderFactory: func(*http.Request) (string, error) {
			return "sdk-route-provider-" + hex.EncodeToString([]byte{byte(created.Add(1))}), nil
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

	service := &Service{
		cfg:           cfg,
		configPath:    configPath,
		coreManager:   coreManager,
		accessManager: accessManager,
		server:        server,
		wsGateway:     relay,
	}

	request := func(method, path, key string, body io.Reader) (*http.Response, []byte) {
		t.Helper()
		req, errRequest := http.NewRequest(method, httpServer.URL+path, body)
		if errRequest != nil {
			t.Fatal(errRequest)
		}
		req.Header.Set("Authorization", "Bearer "+key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, errDo := http.DefaultClient.Do(req)
		if errDo != nil {
			t.Fatal(errDo)
		}
		payload, errRead := io.ReadAll(resp.Body)
		if errClose := resp.Body.Close(); errClose != nil {
			t.Errorf("close response body: %v", errClose)
		}
		if errRead != nil {
			t.Fatal(errRead)
		}
		return resp, payload
	}
	assertModels := func(key string) {
		t.Helper()
		resp, body := request(http.MethodGet, "/v1/models", key, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/models status=%d, want=%d: %s", resp.StatusCode, http.StatusOK, body)
		}
	}
	assertRouteDenied := func(status int, body []byte) {
		t.Helper()
		if status != http.StatusForbidden {
			t.Fatalf("restricted route status=%d, want=%d: %s", status, http.StatusForbidden, body)
		}
		var payload map[string]any
		if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
			t.Fatalf("restricted route returned non-JSON body %q: %v", body, errUnmarshal)
		}
		code, _ := payload["code"].(string)
		if code == "" {
			if failure, ok := payload["error"].(map[string]any); ok {
				code, _ = failure["code"].(string)
			}
		}
		if code != "api_key_route_denied" {
			t.Fatalf("restricted route code=%q, want api_key_route_denied: %s", code, body)
		}
	}
	dial := func(path, key string) (*websocket.Conn, *http.Response, error) {
		t.Helper()
		url := "ws" + strings.TrimPrefix(httpServer.URL, "http") + path
		return websocket.DefaultDialer.Dial(url, http.Header{"Authorization": []string{"Bearer " + key}})
	}
	assertWebsocketAllowed := func(path, key string) {
		t.Helper()
		beforeHandled, beforeCreated := handled.Load(), created.Load()
		conn, response, errDial := dial(path, key)
		if errDial != nil {
			if response != nil {
				body, _ := io.ReadAll(response.Body)
				_ = response.Body.Close()
				t.Fatalf("websocket %s denied unexpectedly (status=%d): %v, %s", path, response.StatusCode, errDial, body)
			}
			t.Fatalf("websocket %s upgrade failed: %v", path, errDial)
		}
		if response == nil || response.StatusCode != http.StatusSwitchingProtocols {
			_ = conn.Close()
			t.Fatalf("websocket %s response=%v, want status=%d", path, response, http.StatusSwitchingProtocols)
		}
		if provider := <-connected; provider == "" {
			_ = conn.Close()
			t.Fatal("websocket upgrade did not notify relay connection")
		}
		if handled.Load() != beforeHandled+1 || created.Load() != beforeCreated+1 {
			_ = conn.Close()
			t.Fatalf("websocket %s relay handled=%d created=%d, want one of each", path, handled.Load()-beforeHandled, created.Load()-beforeCreated)
		}
		if errClose := conn.Close(); errClose != nil {
			t.Errorf("close websocket %s: %v", path, errClose)
		}
	}
	assertWebsocketDenied := func(path, key string) {
		t.Helper()
		beforeHandled, beforeCreated := handled.Load(), created.Load()
		conn, response, errDial := dial(path, key)
		if conn != nil {
			if errClose := conn.Close(); errClose != nil {
				t.Errorf("close unexpected websocket %s: %v", path, errClose)
			}
		}
		if response == nil {
			t.Fatalf("denied websocket %s has no HTTP response: %v", path, errDial)
		}
		body, errRead := io.ReadAll(response.Body)
		if errClose := response.Body.Close(); errClose != nil {
			t.Errorf("close denied websocket response body: %v", errClose)
		}
		if errRead != nil {
			t.Fatal(errRead)
		}
		if errDial == nil {
			t.Fatalf("websocket %s unexpectedly upgraded", path)
		}
		assertRouteDenied(response.StatusCode, body)
		if handled.Load() != beforeHandled || created.Load() != beforeCreated {
			t.Fatalf("denied websocket %s reached relay: handled=%d created=%d", path, handled.Load()-beforeHandled, created.Load()-beforeCreated)
		}
	}

	assertModels(restrictedKey)
	assertWebsocketAllowed("/v1/ws", restrictedKey)
	assertModels(unrestrictedKey)
	assertWebsocketAllowed("/v1/ws", unrestrictedKey)

	digest := sha256.Sum256([]byte(restrictedKey))
	restricted := cfg.CloneForRuntime()
	restricted.APIKeyRoutes = []config.APIKeyRoute{{
		KeySHA256: hex.EncodeToString(digest[:]),
		Allow:     []string{"GET /v1/models", "POST /v1/realtime/client_secrets"},
	}}
	if len(restricted.APIKeyPolicies) != 0 {
		t.Fatal("route-scoped client keys must remain separate from api-key-policies")
	}
	if !restricted.Plugins.Enabled {
		t.Fatal("test config must keep plugins enabled while applying route rules")
	}
	if !service.applyConfigUpdateWithAuthSynthesis(ctx, restricted, false) {
		t.Fatal("service rejected route-rule addition")
	}
	if service.server != server || len(service.cfg.APIKeyRoutes) != 1 {
		t.Fatal("route-rule addition replaced the live API server or failed to publish its config")
	}
	assertModels(restrictedKey)
	assertWebsocketDenied("/v1/ws", restrictedKey)
	assertModels(unrestrictedKey)
	assertWebsocketAllowed("/v1/ws", unrestrictedKey)

	// A client secret inherits its issuer principal; route enforcement must not
	// turn that derived credential into an unrestricted client.
	secretResponse, secretBody := request(http.MethodPost, "/v1/realtime/client_secrets", restrictedKey, strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
	if secretResponse.StatusCode != http.StatusOK {
		t.Fatalf("create restricted issuer client secret status=%d: %s", secretResponse.StatusCode, secretBody)
	}
	var secret struct {
		Value string `json:"value"`
	}
	if errUnmarshal := json.Unmarshal(secretBody, &secret); errUnmarshal != nil || secret.Value == "" {
		t.Fatalf("decode client secret response: value=%q err=%v body=%s", secret.Value, errUnmarshal, secretBody)
	}
	assertWebsocketDenied("/v1/realtime", secret.Value)

	unrestricted := restricted.CloneForRuntime()
	unrestricted.APIKeyRoutes = nil
	if !service.applyConfigUpdateWithAuthSynthesis(ctx, unrestricted, false) {
		t.Fatal("service rejected route-rule removal")
	}
	if service.server != server || len(service.cfg.APIKeyRoutes) != 0 {
		t.Fatal("route-rule removal replaced the live API server or failed to publish its config")
	}
	assertModels(restrictedKey)
	assertWebsocketAllowed("/v1/ws", restrictedKey)
	assertModels(unrestrictedKey)
	assertWebsocketAllowed("/v1/ws", unrestrictedKey)
}
