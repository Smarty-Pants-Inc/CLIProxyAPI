package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
)

// Keep: guard the client-key trust boundary on real server authentication paths.
func TestAPIKeyRoutesReviewOptionsPreflight(t *testing.T) {
	initial := routeTestConfig("GET /v1/models")
	initial.RemoteManagement.SecretKey = "synthetic-management-secret"
	s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))

	var optionsHandlerCalls atomic.Int32
	var websocketHandlerCalls atomic.Int32
	protectedPaths := []string{
		"/v1/models",
		"/v1/live",
		"/backend-api/codex/responses",
		"/v1beta/models",
		"/openai/v1/videos",
		"/v1/realtime",
		"/review-options-ws",
	}
	s.AttachWebsocketRoute("/review-options-ws", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		websocketHandlerCalls.Add(1)
	}))
	for _, path := range protectedPaths {
		s.engine.OPTIONS(path, func(c *gin.Context) {
			optionsHandlerCalls.Add(1)
			c.Status(http.StatusAccepted)
		})
	}

	// A configured GET rule does not authorize an OPTIONS preflight to that path.
	for _, path := range protectedPaths {
		requireReviewRouteDenial(t, reviewOptionsRequest(s, path, "Bearer "+routeRestrictedKey))
	}

	// Unrestricted and unauthenticated/invalid preflights retain the global CORS behavior.
	for _, authorization := range []string{"Bearer " + routeUnrestrictedKey, "", "Bearer synthetic-invalid"} {
		requireReviewPreflight(t, reviewOptionsRequest(s, "/v1/models", authorization))
	}
	for _, path := range []string{"/healthz", "/v8/management/config"} {
		requireReviewPreflight(t, reviewOptionsRequest(s, path, "Bearer "+routeRestrictedKey))
	}

	allowed := make([]string, 0, len(protectedPaths))
	for _, path := range protectedPaths {
		allowed = append(allowed, "OPTIONS "+path)
	}
	updated := routeTestConfig(allowed...)
	applyTestRoutes(t, s, initial, updated)
	for _, path := range protectedPaths {
		requireReviewPreflight(t, reviewOptionsRequest(s, path, "Bearer "+routeRestrictedKey))
	}
	if got := optionsHandlerCalls.Load(); got != 0 {
		t.Errorf("OPTIONS route handlers executed %d times during preflight", got)
	}
	if got := websocketHandlerCalls.Load(); got != 0 {
		t.Errorf("dynamic WebSocket handler executed %d times during preflight", got)
	}
}

func TestAPIKeyRoutesReviewRealtimeSecretOptions(t *testing.T) {
	initial := routeTestConfig()
	s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))
	secret := mintRouteClientSecret(t, s, routeRestrictedKey, "/v1/realtime/client_secrets", false)

	var optionsHandlerCalls atomic.Int32
	s.engine.OPTIONS("/v1/realtime", func(c *gin.Context) {
		optionsHandlerCalls.Add(1)
		c.Status(http.StatusAccepted)
	})

	issuerRestricted := routeTestConfig("POST /v1/realtime/client_secrets")
	applyTestRoutes(t, s, initial, issuerRestricted)
	authorization := "Bearer " + secret
	requireReviewRouteDenial(t, reviewOptionsRequest(s, "/v1/realtime", authorization))

	issuerAllowed := routeTestConfig("POST /v1/realtime/client_secrets", "OPTIONS /v1/realtime")
	applyTestRoutes(t, s, issuerRestricted, issuerAllowed)
	requireReviewPreflight(t, reviewOptionsRequest(s, "/v1/realtime", authorization))
	if got := optionsHandlerCalls.Load(); got != 0 {
		t.Errorf("Realtime OPTIONS handler executed %d times during preflight", got)
	}
}

func TestAPIKeyRoutesReviewMappedPluginPrincipalAndIssuedSecret(t *testing.T) {
	restrictedConfig := routeTestConfig("GET /v1beta/models")
	nativeServer := newTestServerWithConfig(t, restrictedConfig, WithRequestLoggerFactory(nil))
	requireReviewRouteDenial(t, routeRequest(nativeServer, http.MethodGet, "/v1/models", routeRestrictedKey, ""))

	initial := routeTestConfig()
	initial.Plugins.Enabled = true
	s := newTestServerWithConfig(t, initial, WithRequestLoggerFactory(nil))
	installReviewRoutePlugin(t, s)

	secret := mintReviewRoutePluginSecret(t, s)
	secretRequest := httptest.NewRequest(http.MethodGet, "/v1/realtime", nil)
	secretRequest.Header.Set("Authorization", "Bearer "+secret)
	auth, matched, err := s.codexLiveHandler.AuthenticateClientSecret(secretRequest)
	if err != nil || !matched {
		t.Fatalf("authenticate plugin-issued secret: matched=%v err=%v", matched, err)
	}
	if len(auth.IssuerRouteKeyDigests) != 0 {
		t.Errorf("plugin identity was attributed as a client-key digest: %v", auth.IssuerRouteKeyDigests)
	}

	applyTestRoutes(t, s, initial, restrictedConfig)
	pluginRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	pluginRequest.Header.Set("X-Audit-Plugin", "synthetic-plugin-token")
	pluginResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(pluginResponse, pluginRequest)
	if pluginResponse.Code != http.StatusOK {
		t.Errorf("plugin-authenticated request using a mapped account matching a configured key: status=%d body=%s", pluginResponse.Code, pluginResponse.Body.String())
	}

	secretResponse := routeRequest(s, http.MethodGet, "/v1/realtime", secret, "")
	if secretResponse.Code != http.StatusUpgradeRequired {
		t.Errorf("plugin-issued secret became restricted by its coincidentally matching account name: status=%d body=%s", secretResponse.Code, secretResponse.Body.String())
	}

	// A plugin-authenticated request with a standard restricted-key candidate remains restricted.
	standardRequest := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	standardRequest.Header.Set("Authorization", "Bearer "+routeRestrictedKey)
	standardResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(standardResponse, standardRequest)
	requireReviewRouteDenial(t, standardResponse)
}

func TestAPIKeyRoutesReviewNativeSelectedAuthorizationIgnoresLowerScopedCandidates(t *testing.T) {
	s := newTestServerWithConfig(t, routeTestConfig("GET /v1beta/models"), WithRequestLoggerFactory(nil))
	for _, source := range []string{"X-Goog-Api-Key", "X-Api-Key", "key", "auth_token"} {
		t.Run(source, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+routeUnrestrictedKey)
			switch source {
			case "X-Goog-Api-Key", "X-Api-Key":
				req.Header.Set(source, routeRestrictedKey)
			default:
				req.URL.RawQuery = source + "=" + routeRestrictedKey
			}
			rr := httptest.NewRecorder()
			s.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("lower-priority %s credential overrode selected unrestricted Authorization key: status=%d body=%s", source, rr.Code, rr.Body.String())
			}
		})
	}
}

func reviewOptionsRequest(s *Server, path, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodOptions, path, nil)
	req.Header.Set("Origin", "https://client.example.invalid")
	req.Header.Set("Access-Control-Request-Method", http.MethodGet)
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

func requireReviewPreflight(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status=%d want=204; body=%s", rr.Code, rr.Body.String())
		return
	}
	if rr.Body.Len() != 0 {
		t.Errorf("preflight body=%q want empty", rr.Body.String())
	}
}

func requireReviewRouteDenial(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusForbidden {
		t.Errorf("route status=%d want=403 route_denied; body=%s", rr.Code, rr.Body.String())
		return
	}
	requireRouteDenial(t, rr)
}

const reviewRoutePluginIdentifier = "plugin:synthetic-route-review:custom-header"

type reviewRoutePlugin struct{}

func (reviewRoutePlugin) Identifier() string { return reviewRoutePluginIdentifier }

func (p reviewRoutePlugin) Authenticate(_ context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	principal := ""
	switch {
	case r.Header.Get("X-Audit-Plugin") == "synthetic-plugin-token":
		principal = routeRestrictedKey
	case r.Header.Get("Authorization") == "Bearer "+routeRestrictedKey:
		principal = "synthetic-plugin-account"
	default:
		return nil, sdkaccess.NewNotHandledError()
	}
	return &sdkaccess.Result{
		Provider:  p.Identifier(),
		Principal: principal,
		Metadata:  map[string]string{"source": "X-Audit-Plugin"},
	}, nil
}

func installReviewRoutePlugin(t *testing.T, s *Server) {
	t.Helper()
	provider := reviewRoutePlugin{}
	sdkaccess.RegisterProvider(provider.Identifier(), provider)
	sdkaccess.SetExclusiveProvider(provider.Identifier())
	t.Cleanup(func() {
		sdkaccess.ClearExclusiveProvider()
		sdkaccess.UnregisterProvider(provider.Identifier())
	})
	s.accessManager.SetProviders(sdkaccess.RegisteredProviders())
	if providers := s.accessManager.Providers(); len(providers) != 1 || providers[0].Identifier() != provider.Identifier() {
		t.Fatalf("configured providers were not replaced by the synthetic plugin: %v", providers)
	}
}

func mintReviewRoutePluginSecret(t *testing.T, s *Server) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/realtime/client_secrets", strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Audit-Plugin", "synthetic-plugin-token")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("plugin client-secret creation status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode plugin client-secret response: %v", err)
	}
	if response.Value == "" {
		t.Fatal("plugin client-secret response contained no value")
	}
	return response.Value
}
