package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/access"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

const routeRestrictedKey = "synthetic-route-restricted"
const routeUnrestrictedKey = "synthetic-route-unrestricted"

func routeTestConfig(allow ...string) *config.Config {
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{routeRestrictedKey, routeUnrestrictedKey}}}
	if allow != nil {
		cfg.APIKeyRoutes = []config.APIKeyRoute{{KeySHA256: config.APIKeyDigest(routeRestrictedKey), Allow: allow}}
	}
	return cfg
}

func routeRequest(s *Server, method, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func requireRouteDenial(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || response.Error.Code != "api_key_route_denied" || response.Error.Message == "" || response.Error.Type != "permission_error" {
		t.Fatalf("invalid route-denied error: %s (decode=%v)", rr.Body.String(), err)
	}
	if rr.Header().Get("Upgrade") != "" {
		t.Fatal("denial advertised an upgrade")
	}
}

func applyTestRoutes(t *testing.T, s *Server, old, next *config.Config) {
	t.Helper()
	if _, err := access.ApplyAccessProviders(s.accessManager, old, next); err != nil {
		t.Fatalf("ApplyAccessProviders: %v", err)
	}
}

// Keep: client-key trust boundary; exercise real registered handlers with no upstream credentials.
func TestAPIKeyRoutesServerGroups(t *testing.T) {
	s := newTestServerWithConfig(t, routeTestConfig(), WithRequestLoggerFactory(nil))
	for _, route := range []string{
		"GET /v1/models", "POST /v1/chat/completions", "POST /v1/responses", "POST /v1/responses/compact",
		"POST /v1/live", "GET /v1/live/call-123", "POST /backend-api/codex/responses", "POST /backend-api/codex/responses/compact",
		"GET /v1beta/models", "POST /v1beta/models/synthetic:generateContent", "POST /openai/v1/videos",
		"GET /v1/realtime", "POST /v1/realtime", "POST /v1/realtime/calls", "GET /v1/realtime/calls/call-123",
		"POST /v1/realtime/client_secrets", "POST /v1/realtime/sessions", "POST /v1/realtime/transcription_sessions",
		"GET /v1/realtime/translations", "POST /v1/realtime/translations", "POST /v1/realtime/translations/client_secrets",
		"POST /v1/realtime/calls/call-123/hangup", "POST /v1/realtime/calls/call-123/accept",
		"POST /v1/realtime/calls/call-123/reject", "POST /v1/realtime/calls/call-123/refer",
	} {
		t.Run(route, func(t *testing.T) {
			parts := strings.SplitN(route, " ", 2)
			method, path := parts[0], parts[1]
			baseline := routeRequest(s, method, path, routeUnrestrictedKey, "{}")
			if baseline.Code == 401 || baseline.Code == 403 || baseline.Code >= 300 && baseline.Code < 400 {
				t.Fatalf("baseline did not reach handler: %d %s", baseline.Code, baseline.Body.String())
			}
			deny := routeTestConfig("GET /healthz")
			applyTestRoutes(t, s, nil, deny)
			requireRouteDenial(t, routeRequest(s, method, path+"?ignored=query", routeRestrictedKey, "{}"))
			unrestricted := routeRequest(s, method, path, routeUnrestrictedKey, "{}")
			if unrestricted.Code != baseline.Code {
				t.Fatalf("unrestricted changed: %d -> %d", baseline.Code, unrestricted.Code)
			}
			allow := routeTestConfig(method + " " + path + "/")
			applyTestRoutes(t, s, deny, allow)
			allowed := routeRequest(s, method, path, routeRestrictedKey, "{}")
			if allowed.Code != baseline.Code {
				t.Fatalf("allowed did not reach handler: got %d want %d; body=%s", allowed.Code, baseline.Code, allowed.Body.String())
			}
		})
	}
}

// Keep: CORS must check scoped credentials without invoking handlers or quota admission.
func TestAPIKeyRoutesPreflight(t *testing.T) {
	for _, wsAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "optional-ws", true: "authenticated-ws"}[wsAuth], func(t *testing.T) {
			cfg := routeTestConfig("GET /v1/models")
			cfg.WebsocketAuth = wsAuth
			s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
			var calls atomic.Int32
			for _, path := range []string{"/preflight-attached-ws", "/preflight-slash-ws/"} {
				s.AttachWebsocketRoute(path, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			}
			for _, path := range []string{
				"/v1/models", "/v1/not-allowed", "/v1/live", "/v1/responses",
				"/backend-api/codex/responses", "/v1beta/models", "/openai/v1/videos",
				"/v1/realtime", "/v1/realtime/calls", "/v1/realtime/calls/call-123",
				"/v1/realtime/translations", "/v1/realtime/client_secrets", "/v1/realtime/sessions",
				"/preflight-attached-ws", "/preflight-attached-ws/", "/preflight-attached-ws///",
				"/preflight-slash-ws", "/preflight-slash-ws/",
			} {
				t.Run(path, func(t *testing.T) {
					applyTestRoutes(t, s, nil, cfg)
					requireRouteDenial(t, routeRequest(s, "OPTIONS", path, routeRestrictedKey, ""))
					for _, key := range []string{"", "synthetic-invalid", routeUnrestrictedKey} {
						rr := routeRequest(s, "OPTIONS", path, key, "")
						if rr.Code != 204 || rr.Body.Len() != 0 || rr.Header().Get("Access-Control-Allow-Origin") != "*" {
							t.Fatalf("ordinary preflight changed: %d %s", rr.Code, rr.Body.String())
						}
					}
					allow := routeTestConfig("OPTIONS " + path)
					applyTestRoutes(t, s, cfg, allow)
					if rr := routeRequest(s, "OPTIONS", path, routeRestrictedKey, ""); rr.Code != 204 || rr.Body.Len() != 0 {
						t.Fatalf("allowed preflight invoked handler: %d %s", rr.Code, rr.Body.String())
					}
				})
			}
			applyTestRoutes(t, s, nil, cfg)
			for _, path := range []string{"/", "/healthz", "/management.html", "/v8/management/config", "/v0/management/config", "/codex/callback", "/unrelated-public"} {
				if rr := routeRequest(s, "OPTIONS", path, routeRestrictedKey, ""); rr.Code != 204 {
					t.Fatalf("client auth extended to public/management route %s: %d", path, rr.Code)
				}
			}
			// The successful native credential wins, not the lower restricted candidate.
			req := httptest.NewRequest("OPTIONS", "/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+routeUnrestrictedKey)
			req.Header.Set("X-Api-Key", routeRestrictedKey)
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != 204 || calls.Load() != 0 {
				t.Fatalf("preflight precedence/handler bypass changed: status=%d calls=%d", rr.Code, calls.Load())
			}
		})
	}
}

func TestAPIKeyRoutesPreflightSkipsKeyPolicy(t *testing.T) {
	cfg := routeTestConfig("OPTIONS /v1/responses")
	cfg.WebsocketAuth = true
	zero := int64(0)
	cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: config.APIKeyDigest(routeRestrictedKey), AllowedAuths: []string{}, DailyRequestCap: &zero}}
	s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
	if rr := routeRequest(s, "OPTIONS", "/v1/responses", routeRestrictedKey, "not-json"); rr.Code != 204 || rr.Body.Len() != 0 {
		t.Fatalf("preflight ran policy admission: %d %s", rr.Code, rr.Body.String())
	}
	next := *cfg
	next.APIKeyRoutes = routeTestConfig("POST /v1/responses").APIKeyRoutes
	applyTestRoutes(t, s, cfg, &next)
	requireRouteDenial(t, routeRequest(s, "OPTIONS", "/v1/responses", routeRestrictedKey, "not-json"))
}

func TestAPIKeyRoutesRealtimePreflight(t *testing.T) {
	s := newTestServerWithConfig(t, routeTestConfig(), WithRequestLoggerFactory(nil))
	token := mintRouteClientSecret(t, s, routeRestrictedKey, "/v1/realtime/client_secrets", false)
	applyTestRoutes(t, s, nil, routeTestConfig("POST /v1/realtime/client_secrets"))
	for _, path := range []string{"/v1/realtime", "/v1/realtime///", "/v1/realtime/calls", "/v1/realtime/calls/call-123", "/v1/realtime/translations"} {
		requireRouteDenial(t, routeRequest(s, "OPTIONS", path, token, ""))
		if rr := routeRequest(s, "OPTIONS", path, "ek_synthetic-invalid", ""); rr.Code != 204 {
			t.Fatalf("invalid delegate changed preflight: %d", rr.Code)
		}
		applyTestRoutes(t, s, nil, routeTestConfig("OPTIONS "+path))
		if rr := routeRequest(s, "OPTIONS", path, token, ""); rr.Code != 204 || rr.Body.Len() != 0 {
			t.Fatalf("allowed delegate preflight: %d %s", rr.Code, rr.Body.String())
		}
		applyTestRoutes(t, s, nil, routeTestConfig("POST /v1/realtime/client_secrets"))
	}
}

func TestAPIKeyRoutesExactMethodPathAndReload(t *testing.T) {
	initial := routeTestConfig()
	s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))
	if rr := routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("initial request: %d", rr.Code)
	}
	wrongMethod := routeTestConfig("POST /v1/models")
	applyTestRoutes(t, s, initial, wrongMethod)
	requireRouteDenial(t, routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""))
	anyMethod := routeTestConfig("/v1/models/")
	applyTestRoutes(t, s, wrongMethod, anyMethod)
	if rr := routeRequest(s, "GET", "/v1/models?query=ignored", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("any-method/trailing-slash allow: %d %s", rr.Code, rr.Body.String())
	}
	requireRouteDenial(t, routeRequest(s, "GET", "/v1/models/not-a-prefix-match", routeRestrictedKey, ""))
	removed := routeTestConfig()
	applyTestRoutes(t, s, anyMethod, removed)
	if rr := routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("removed restriction still enforced: %d %s", rr.Code, rr.Body.String())
	}
	invalid := routeTestConfig("GET /v1/*")
	if _, err := access.ApplyAccessProviders(s.accessManager, removed, invalid); err == nil {
		t.Fatal("wildcard policy accepted")
	}
	if rr := routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("invalid update changed active snapshot: %d", rr.Code)
	}
	// Also cross the server reload boundary, not just the access API.
	s.UpdateClients(routeTestConfig("GET /healthz"))
	requireRouteDenial(t, routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""))
	s.UpdateClients(routeTestConfig())
	if rr := routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("server route removal did not apply: %d %s", rr.Code, rr.Body.String())
	}
}

func TestAPIKeyRoutesCredentialCandidatePrecedence(t *testing.T) {
	s := newTestServerWithConfig(t, routeTestConfig("GET /healthz"), WithRequestLoggerFactory(nil))
	for _, source := range []string{"authorization", "x-goog-api-key", "x-api-key", "key", "auth_token"} {
		t.Run(source, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/models", nil)
			switch source {
			case "authorization":
				req.Header.Set("Authorization", "Bearer "+routeRestrictedKey)
			case "key", "auth_token":
				req.URL.RawQuery = url.Values{source: {routeRestrictedKey}}.Encode()
			default:
				req.Header.Set(source, routeRestrictedKey)
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			requireRouteDenial(t, rr)
		})
	}
	for _, lower := range []string{"X-Goog-Api-Key", "X-Api-Key", "key", "auth_token"} {
		t.Run("unrestricted-wins-"+lower, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+routeUnrestrictedKey)
			if strings.HasPrefix(lower, "X-") {
				req.Header.Set(lower, routeRestrictedKey)
			} else {
				req.URL.RawQuery = url.Values{lower: {routeRestrictedKey}}.Encode()
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != 200 {
				t.Fatalf("lower-priority rejected credential restricted successful key: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
	// Earlier invalid candidates do not hide the actual selected restricted key.
	req := httptest.NewRequest("GET", "/v1/models?key="+routeRestrictedKey, nil)
	req.Header.Set("Authorization", "Bearer synthetic-invalid")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	requireRouteDenial(t, rr)
}

type routeMappedPluginProvider struct{ principal string }

func (routeMappedPluginProvider) Identifier() string { return "plugin:synthetic-route:mapped" }
func (p routeMappedPluginProvider) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if r.Header.Get("Authorization") == "" && r.Header.Get("X-Api-Key") == "" && r.URL.Query().Get("key") == "" {
		return nil, sdkaccess.NewNotHandledError()
	}
	principal := p.principal
	if principal == "" {
		principal = "synthetic-mapped-account"
	}
	return &sdkaccess.Result{Provider: p.Identifier(), Principal: principal, Metadata: map[string]string{"source": "authorization", "route_allowed": "true"}}, nil
}

func installExclusiveRoutePlugin(t *testing.T, s *Server, principal ...string) {
	t.Helper()
	provider := routeMappedPluginProvider{}
	if len(principal) != 0 {
		provider.principal = principal[0]
	}
	sdkaccess.RegisterProvider(provider.Identifier(), provider)
	sdkaccess.SetExclusiveProvider(provider.Identifier())
	t.Cleanup(func() {
		sdkaccess.ClearExclusiveProvider()
		sdkaccess.UnregisterProvider(provider.Identifier())
	})
	s.accessManager.SetProviders(sdkaccess.RegisteredProviders())
	if providers := s.accessManager.Providers(); len(providers) != 1 || providers[0].Identifier() != provider.Identifier() {
		t.Fatalf("config provider was not excluded: %v", providers)
	}
}

func TestAPIKeyRoutesExclusiveMappedPlugin(t *testing.T) {
	cfg := routeTestConfig("GET /v1beta/models")
	cfg.Plugins.Enabled = true
	s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
	installExclusiveRoutePlugin(t, s)
	for _, source := range []string{"Authorization", "X-Api-Key", "key"} {
		req := httptest.NewRequest("GET", "/v1/models", nil)
		switch source {
		case "Authorization":
			req.Header.Set(source, "Bearer "+routeRestrictedKey)
		case "key":
			req.URL.RawQuery = url.Values{source: {routeRestrictedKey}}.Encode()
		default:
			req.Header.Set(source, routeRestrictedKey)
		}
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)
		requireRouteDenial(t, rr)
	}
	if rr := routeRequest(s, "GET", "/v1beta/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("allowed plugin-authenticated route: %d %s", rr.Code, rr.Body.String())
	}
	if rr := routeRequest(s, "GET", "/v1/models", routeUnrestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("unrestricted plugin key changed: %d %s", rr.Code, rr.Body.String())
	}
	applyTestRoutes(t, s, cfg, routeTestConfig())
	if rr := routeRequest(s, "GET", "/v1/models", routeRestrictedKey, ""); rr.Code != 200 {
		t.Fatalf("plugin reload removal did not apply: %d %s", rr.Code, rr.Body.String())
	}
}

func mintRouteClientSecret(t *testing.T, s *Server, issuer, endpoint string, extraRestricted bool) string {
	t.Helper()
	req := httptest.NewRequest("POST", endpoint, strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
	req.Header.Set("Authorization", "Bearer "+issuer)
	if extraRestricted {
		req.Header.Set("X-Api-Key", routeRestrictedKey)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("mint secret: %d %s", rr.Code, rr.Body.String())
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
		t.Fatal("no local client secret issued")
	}
	return response.Value
}

func TestAPIKeyRoutesRealtimeIssuerAndReload(t *testing.T) {
	for _, mapped := range []bool{false, true} {
		for _, endpoint := range []string{"/v1/realtime/client_secrets", "/v1/realtime/sessions"} {
			t.Run(endpoint+"/mapped="+map[bool]string{false: "false", true: "true"}[mapped], func(t *testing.T) {
				initial := routeTestConfig()
				initial.Plugins.Enabled = mapped
				s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))
				if mapped {
					installExclusiveRoutePlugin(t, s)
				}
				// Both secrets predate any route restrictions.
				restricted := mintRouteClientSecret(t, s, routeRestrictedKey, endpoint, false)
				unrestricted := mintRouteClientSecret(t, s, routeUnrestrictedKey, endpoint, !mapped)
				authRequest := httptest.NewRequest("GET", "/v1/realtime", nil)
				authRequest.Header.Set("Authorization", "Bearer "+restricted)
				authorization, matched, err := s.codexLiveHandler.AuthenticateClientSecret(authRequest)
				wantPrincipal, wantProvider := routeRestrictedKey, sdkaccess.DefaultAccessProviderName
				if mapped {
					wantPrincipal, wantProvider = "synthetic-mapped-account", (routeMappedPluginProvider{}).Identifier()
				}
				if err != nil || !matched || authorization.IssuerPrincipal != wantPrincipal || authorization.IssuerProvider != wantProvider || !reflect.DeepEqual(authorization.IssuerRouteKeyDigests, []string{config.APIKeyDigest(routeRestrictedKey)}) {
					t.Fatalf("issuer identity/attribution changed: matched=%v err=%v issuer=%q/%q digests=%v", matched, err, authorization.IssuerProvider, authorization.IssuerPrincipal, authorization.IssuerRouteKeyDigests)
				}
				deny := routeTestConfig("POST " + endpoint)
				applyTestRoutes(t, s, initial, deny)
				for _, route := range []string{"GET /v1/realtime", "POST /v1/realtime/calls", "GET /v1/realtime/calls/call-123", "POST /v1/realtime/translations"} {
					parts := strings.SplitN(route, " ", 2)
					requireRouteDenial(t, routeRequest(s, parts[0], parts[1], restricted, "{}"))
				}
				if rr := routeRequest(s, "GET", "/v1/realtime", unrestricted, ""); rr.Code != 426 {
					t.Fatalf("unrestricted issuer was restricted: %d %s", rr.Code, rr.Body.String())
				}
				allow := routeTestConfig("POST "+endpoint, "GET /v1/realtime")
				applyTestRoutes(t, s, deny, allow)
				if rr := routeRequest(s, "GET", "/v1/realtime", restricted, ""); rr.Code != 426 {
					t.Fatalf("issuer route allow not applied: %d %s", rr.Code, rr.Body.String())
				}
				applyTestRoutes(t, s, allow, routeTestConfig())
				if rr := routeRequest(s, "GET", "/v1/realtime", restricted, ""); rr.Code != 426 {
					t.Fatalf("issuer route removal not applied: %d %s", rr.Code, rr.Body.String())
				}
			})
		}
	}
}

func TestAPIKeyRoutesRealtimeAttributionCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name, provider string
		known, denied  bool
	}{
		{"legacy-native", sdkaccess.DefaultAccessProviderName, false, true},
		{"legacy-native-alias", "config-api-key", false, true},
		{"known-no-key-native", sdkaccess.DefaultAccessProviderName, true, false},
		{"legacy-plugin", "plugin:synthetic", false, false},
		{"known-no-key-plugin", "plugin:synthetic", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServerWithConfig(t, routeTestConfig("POST /mint"), WithRequestLoggerFactory(nil))
			// Embedded legacy callers can create secrets without Manager context.
			router := gin.New()
			router.POST("/mint", func(c *gin.Context) {
				c.Set("userApiKey", routeRestrictedKey)
				c.Set("accessProvider", tc.provider)
				if tc.known {
					c.Set(sdkaccess.RouteKeyDigestsContextKey, []string(nil))
				}
			}, s.codexLiveHandler.CreateClientSecret)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, httptest.NewRequest("POST", "/mint", strings.NewReader(`{"session":{"type":"realtime"}}`)))
			var response struct {
				Value string `json:"value"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || rr.Code != 200 || response.Value == "" {
				t.Fatalf("legacy mint: status=%d body=%s err=%v", rr.Code, rr.Body.String(), err)
			}
			for _, method := range []string{"GET", "OPTIONS"} {
				rr := routeRequest(s, method, "/v1/realtime", response.Value, "")
				if tc.denied {
					requireRouteDenial(t, rr)
					continue
				}
				want := 426
				if method == "OPTIONS" {
					want = 204
				}
				if rr.Code != want {
					t.Fatalf("known/legacy attribution changed: status=%d want=%d body=%s", rr.Code, want, rr.Body.String())
				}
			}
		})
	}
}

func TestAPIKeyRoutesRealWebsocketUpgrades(t *testing.T) {
	for _, wsAuth := range []bool{false, true} {
		t.Run(map[bool]string{false: "ws-auth-disabled", true: "ws-auth-enabled"}[wsAuth], func(t *testing.T) {
			cfg := routeTestConfig("GET /healthz")
			cfg.WebsocketAuth = wsAuth
			s := newTestServerWithConfig(t, cfg, WithRequestLoggerFactory(nil))
			var upgrades atomic.Int32
			s.AttachWebsocketRoute("/route-test-ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				upgrades.Add(1)
				_ = conn.Close()
			}))
			httpServer := httptest.NewServer(s.Handler())
			defer httpServer.Close()
			for _, path := range []string{"/v1/responses", "/backend-api/codex/responses", "/route-test-ws"} {
				for _, key := range []string{routeRestrictedKey, routeUnrestrictedKey} {
					probeRouteWebsocket(t, httpServer.URL, path, key, key == routeUnrestrictedKey)
				}
				allow := routeTestConfig("GET " + path)
				allow.WebsocketAuth = wsAuth
				applyTestRoutes(t, s, cfg, allow)
				probeRouteWebsocket(t, httpServer.URL, path, routeRestrictedKey, true)
				applyTestRoutes(t, s, allow, cfg)
			}
			if wsAuth {
				probeRouteWebsocketStatus(t, httpServer.URL, "/route-test-ws", "", 401)
			} else {
				probeRouteWebsocket(t, httpServer.URL, "/route-test-ws", "", true)
				probeRouteWebsocket(t, httpServer.URL, "/route-test-ws", "synthetic-invalid", true)
			}
			for _, credential := range []string{"?key=", "?auth_token="} {
				probeRouteWebsocket(t, httpServer.URL, "/route-test-ws"+credential+url.QueryEscape(routeRestrictedKey), "", false)
			}
			// Genuine upgrade attempts to live/realtime are denied by auth, before
			// their session lookup or OAuth selection (the server has neither).
			for _, path := range []string{"/v1/live/call-123", "/v1/realtime", "/v1/realtime/calls/call-123"} {
				probeRouteWebsocket(t, httpServer.URL, path, routeRestrictedKey, false)
			}
			if upgrades.Load() == 0 {
				t.Fatal("dynamic handler never upgraded an allowed request")
			}
			// Reload add/remove also applies to an already-attached optional-auth route.
			applyTestRoutes(t, s, cfg, routeTestConfig())
			probeRouteWebsocket(t, httpServer.URL, "/route-test-ws", routeRestrictedKey, true)
			applyTestRoutes(t, s, routeTestConfig(), cfg)
			probeRouteWebsocket(t, httpServer.URL, "/route-test-ws", routeRestrictedKey, false)
		})
	}
}

func probeRouteWebsocket(t *testing.T, base, path, key string, allow bool) {
	t.Helper()
	want := http.StatusForbidden
	if allow {
		want = http.StatusSwitchingProtocols
	}
	probeRouteWebsocketStatus(t, base, path, key, want)
}

func probeRouteWebsocketStatus(t *testing.T, base, path, key string, want int) {
	t.Helper()
	headers := http.Header{}
	if key != "" {
		headers.Set("Authorization", "Bearer "+key)
	}
	conn, resp, err := (&websocket.Dialer{}).Dial("ws"+strings.TrimPrefix(base, "http")+path, headers)
	if conn != nil {
		_ = conn.Close()
	}
	if resp == nil {
		t.Fatalf("%s: no handshake response: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want || want == 101 && err != nil || want != 101 && err == nil {
		t.Fatalf("%s: handshake status=%d want=%d err=%v", path, resp.StatusCode, want, err)
	}
	if want == 403 {
		body, errRead := io.ReadAll(resp.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		rr := httptest.NewRecorder()
		rr.Code = resp.StatusCode
		rr.HeaderMap = resp.Header.Clone()
		_, _ = rr.Body.Write(body)
		requireRouteDenial(t, rr)
	}
}
