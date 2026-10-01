package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	proxyconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type policyHTTPExecutor struct {
	mockServerStreamingCaptureExecutor
	ids        []string
	principals []string
}

func (e *policyHTTPExecutor) record(ctx context.Context, selected *auth.Auth) {
	e.ids = append(e.ids, selected.ID)
	if c, ok := ctx.Value("gin").(*gin.Context); ok {
		value, _ := c.Get("userApiKey")
		principal, _ := value.(string)
		e.principals = append(e.principals, principal)
	}
}
func (e *policyHTTPExecutor) Execute(ctx context.Context, selected *auth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(ctx, selected)
	return e.mockServerStreamingCaptureExecutor.Execute(ctx, selected, req, opts)
}
func (e *policyHTTPExecutor) ExecuteStream(ctx context.Context, selected *auth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.record(ctx, selected)
	return e.mockServerStreamingCaptureExecutor.ExecuteStream(ctx, selected, req, opts)
}

func TestAPIKeyPolicyDerivedRealtimeTokenRetainsAdmission(t *testing.T) {
	const key = "synthetic-derived-policy-key"
	digest := sha256.Sum256([]byte(key))
	cfg := &proxyconfig.Config{SDKConfig: proxyconfig.SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []proxyconfig.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}}}}
	server := newTestServerWithConfig(t, cfg)
	mint := httptest.NewRequest(http.MethodPost, "/v1/realtime/client_secrets", strings.NewReader(`{"session":{"type":"realtime","model":"gpt-realtime"}}`))
	mint.Header.Set("Authorization", "Bearer "+key)
	mintResponse := httptest.NewRecorder()
	server.engine.ServeHTTP(mintResponse, mint)
	if mintResponse.Code != http.StatusOK {
		t.Fatalf("mint failed: %d %s", mintResponse.Code, mintResponse.Body.String())
	}
	var token struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(mintResponse.Body.Bytes(), &token); err != nil || token.Value == "" {
		t.Fatal("missing derived token")
	}
	reloaded := cfg.CloneForRuntime()
	reloaded.APIKeyPolicies = nil
	if !server.UpdateClientsContext(context.Background(), reloaded) {
		t.Fatal("policy reload failed")
	}
	call := func() *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls", strings.NewReader("v=0\r\n"))
		request.Header.Set("Content-Type", "application/sdp")
		request.Header.Set("Authorization", "Bearer "+token.Value)
		response := httptest.NewRecorder()
		server.engine.ServeHTTP(response, request)
		return response
	}
	response := call()
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "unavailable for client keys with policies") {
		t.Fatalf("policy removal unconfined token: %d %s", response.Code, response.Body.String())
	}
	reloaded = reloaded.CloneForRuntime()
	reloaded.APIKeys = []string{"other-synthetic-key"}
	if !server.UpdateClientsContext(context.Background(), reloaded) {
		t.Fatal("key revocation reload failed")
	}
	response = call()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked issuer token accepted: %d %s", response.Code, response.Body.String())
	}
}

func TestAPIKeyPolicyHTTPAuthenticationAndReload(t *testing.T) {
	const restricted = "synthetic-http-policy-client"
	digest := sha256.Sum256([]byte(restricted))
	cfg := &proxyconfig.Config{SDKConfig: proxyconfig.SDKConfig{
		APIKeys:        []string{restricted, "unpolicied-http-client"},
		APIKeyPolicies: []proxyconfig.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}},
	}}
	server := newTestServerWithConfig(t, cfg)
	executor := &policyHTTPExecutor{mockServerStreamingCaptureExecutor: mockServerStreamingCaptureExecutor{cfg: cfg}}
	server.handlers.AuthManager.RegisterExecutor(executor)
	for _, a := range []*auth.Auth{
		{ID: "http-policy-denied", Provider: executor.Identifier(), FileName: "denied.json", Attributes: map[string]string{"priority": "100"}},
		{ID: "http-policy-allowed", Provider: executor.Identifier(), FileName: "verified.json"},
	} {
		if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.ID, a.Provider, []*registry.ModelInfo{{ID: "http-key-policy-model"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.ID) })
	}
	request := func(key string, stream bool) *httptest.ResponseRecorder {
		body := `{"model":"http-key-policy-model","input":[],"stream":false}`
		if stream {
			body = `{"model":"http-key-policy-model","input":[],"stream":true}`
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
		// The invalid preferred header must not override the key that actually authenticates.
		req.Header.Set("Authorization", "Bearer invalid-unrestricted-looking-key")
		req.Header.Set("X-Api-Key", key)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		server.engine.ServeHTTP(rr, req)
		return rr
	}
	for _, stream := range []bool{false, true} {
		rr := request(restricted, stream)
		if rr.Code != http.StatusOK {
			t.Fatalf("stream=%v: status=%d body=%s", stream, rr.Code, rr.Body.String())
		}
		if executor.ids[len(executor.ids)-1] != "http-policy-allowed" {
			t.Fatalf("HTTP picked denied credential: %v", executor.ids)
		}
		if executor.principals[len(executor.principals)-1] != restricted {
			t.Fatal("usage principal changed")
		}
	}
	rr := request("unpolicied-http-client", false)
	if rr.Code != http.StatusOK || executor.ids[len(executor.ids)-1] != "http-policy-denied" {
		t.Fatalf("unpolicied path changed: status=%d ids=%v", rr.Code, executor.ids)
	}
	revoked := cfg.CloneForRuntime()
	revoked.APIKeyPolicies[0].AllowedAuths = nil
	if !server.UpdateClientsContext(context.Background(), revoked) {
		t.Fatal("reload failed")
	}
	calls := len(executor.ids)
	rr = request(restricted, false)
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "allowlist") || len(executor.ids) != calls {
		t.Fatalf("revoked request escaped: status=%d calls=%v body=%s", rr.Code, executor.ids, rr.Body.String())
	}
}
