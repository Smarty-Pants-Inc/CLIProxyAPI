package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

type routeCustomSourcePluginProvider struct{}

func (routeCustomSourcePluginProvider) Identifier() string { return "plugin:synthetic-custom-source" }
func (p routeCustomSourcePluginProvider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if r.Header.Get("X-Audit-Plugin") != "synthetic-custom-credential" {
		return nil, sdkaccess.NewInvalidCredentialError()
	}
	return &sdkaccess.Result{Provider: p.Identifier(), Principal: routeRestrictedKey}, nil
}

// Keep: a custom-source plugin's mapped account must not become a key, directly or by delegation.
func TestAPIKeyRoutesCustomSourcePlugin(t *testing.T) {
	cfg := routeTestConfig("POST /v1/realtime/client_secrets", "POST /v1/realtime/sessions")
	cfg.Plugins.Enabled = true
	s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
	s.accessManager.SetProviders([]sdkaccess.Provider{routeCustomSourcePluginProvider{}})
	request := func(method, path, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
		req.Header.Set("X-Audit-Plugin", "synthetic-custom-credential")
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		return rr
	}
	if rr := request("GET", "/v1/models", ""); rr.Code != 200 {
		t.Fatalf("custom-source mapped account falsely denied: %d %s", rr.Code, rr.Body.String())
	}
	if rr := request("OPTIONS", "/v1/models", ""); rr.Code != 204 {
		t.Fatalf("custom-source preflight falsely denied: %d %s", rr.Code, rr.Body.String())
	}
	// Counterexample: a real restricted standard candidate remains enforced.
	requireRouteDenial(t, request("GET", "/v1/models", routeRestrictedKey))
	requireRouteDenial(t, request("OPTIONS", "/v1/models", routeRestrictedKey))
	for _, endpoint := range []string{"/v1/realtime/client_secrets", "/v1/realtime/sessions"} {
		rr := request("POST", endpoint, "")
		if rr.Code != 200 {
			t.Fatalf("custom-source mint: %d %s", rr.Code, rr.Body.String())
		}
		var response struct {
			Value        string `json:"value"`
			ClientSecret struct {
				Value string `json:"value"`
			} `json:"client_secret"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Value == "" {
			response.Value = response.ClientSecret.Value
		}
		if response.Value == "" {
			t.Fatal("missing client secret")
		}
		authRequest := httptest.NewRequest("GET", "/v1/realtime", nil)
		authRequest.Header.Set("Authorization", "Bearer "+response.Value)
		authorization, matched, err := s.codexLiveHandler.AuthenticateClientSecret(authRequest)
		if err != nil || !matched || authorization.IssuerPrincipal != routeRestrictedKey || authorization.IssuerProvider != (routeCustomSourcePluginProvider{}).Identifier() || len(authorization.IssuerRouteKeyDigests) != 0 {
			t.Fatalf("false issuer attribution: %+v matched=%v err=%v", authorization, matched, err)
		}
		if rr := routeRequest(s, "GET", "/v1/realtime", response.Value, ""); rr.Code != 426 {
			t.Fatalf("custom-source delegate falsely denied: %d %s", rr.Code, rr.Body.String())
		}
		if rr := routeRequest(s, "OPTIONS", "/v1/realtime", response.Value, ""); rr.Code != 204 {
			t.Fatalf("custom-source delegate preflight falsely denied: %d %s", rr.Code, rr.Body.String())
		}
		// The same plugin, same mapped principal, but a real supplied key:
		// its delegated restriction must still be checked.
		rr = request("POST", endpoint, routeRestrictedKey)
		if rr.Code != 200 {
			t.Fatalf("restricted plugin mint: %d %s", rr.Code, rr.Body.String())
		}
		response.Value, response.ClientSecret.Value = "", ""
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Value == "" {
			response.Value = response.ClientSecret.Value
		}
		if response.Value == "" {
			t.Fatal("missing restricted client secret")
		}
		requireRouteDenial(t, routeRequest(s, "GET", "/v1/realtime", response.Value, ""))
		requireRouteDenial(t, routeRequest(s, "OPTIONS", "/v1/realtime", response.Value, ""))
	}
}

// Keep: plugin identity is not a credential, even if it equals a configured key.
func TestAPIKeyRoutesExclusivePluginIdentityCollision(t *testing.T) {
	for _, mappedPrincipal := range []string{routeRestrictedKey, routeUnrestrictedKey} {
		t.Run(mappedPrincipal, func(t *testing.T) {
			initial := routeTestConfig()
			initial.Plugins.Enabled = true
			s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))
			installExclusiveRoutePlugin(t, s, mappedPrincipal)
			restricted := mintRouteClientSecret(t, s, routeRestrictedKey, "/v1/realtime/client_secrets", false)
			unrestricted := mintRouteClientSecret(t, s, routeUnrestrictedKey, "/v1/realtime/client_secrets", false)
			deny := routeTestConfig("POST /v1/realtime/client_secrets")
			applyTestRoutes(t, s, initial, deny)
			requireRouteDenial(t, routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""))
			requireRouteDenial(t, routeRequest(s, "GET", "/v1/realtime", restricted, ""))
			if rr := routeRequest(s, "GET", "/v1/models", routeUnrestrictedKey, ""); rr.Code != 200 {
				t.Fatalf("mapped account was mistaken for another key: %d %s", rr.Code, rr.Body.String())
			}
			if rr := routeRequest(s, "GET", "/v1/realtime", unrestricted, ""); rr.Code != 426 {
				t.Fatalf("mapped issuer was mistaken for another key: %d %s", rr.Code, rr.Body.String())
			}
			// Even if the mapped principal equals a supplied unrestricted key,
			// arbitrary plugin source metadata does not identify a winning key.
			req := httptest.NewRequest("GET", "/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+routeUnrestrictedKey)
			req.Header.Set("X-Api-Key", routeRestrictedKey)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			requireRouteDenial(t, rr)
		})
	}
}

func TestAPIKeyRoutesOptionalWebsocketExclusivePlugin(t *testing.T) {
	cfg := routeTestConfig("GET /v1/models")
	cfg.Plugins.Enabled = true
	cfg.WebsocketAuth = false
	s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
	installExclusiveRoutePlugin(t, s)
	s.AttachWebsocketRoute("/plugin-route-ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			_ = conn.Close()
		}
	}))
	httpServer := httptest.NewServer(s.Handler())
	defer httpServer.Close()
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", routeRestrictedKey, false)
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", routeUnrestrictedKey, true)
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", "", true)
	// The same snapshot must survive replacement by a successful exclusive plugin.
	s.accessManager.SetProviders(sdkaccess.RegisteredProviders())
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", routeRestrictedKey, false)
	allow := routeTestConfig("GET /plugin-route-ws")
	applyTestRoutes(t, s, cfg, allow)
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", routeRestrictedKey, true)
	applyTestRoutes(t, s, allow, routeTestConfig())
	probeRouteWebsocket(t, httpServer.URL, "/plugin-route-ws", routeRestrictedKey, true)
}
