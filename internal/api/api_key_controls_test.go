package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type meteredPolicyHTTPExecutor struct {
	mockServerStreamingCaptureExecutor
	calls atomic.Int32
}

func (e *meteredPolicyHTTPExecutor) publish(ctx context.Context, a *auth.Auth, req coreexecutor.Request) {
	e.calls.Add(1)
	helps.NewUsageReporter(ctx, e.Identifier(), req.Model, a).Publish(ctx, coreusage.Detail{InputTokens: 3, OutputTokens: 2, ReasoningTokens: 100, TotalTokens: 1000})
}
func (e *meteredPolicyHTTPExecutor) Execute(ctx context.Context, a *auth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.publish(ctx, a, req)
	return e.mockServerStreamingCaptureExecutor.Execute(ctx, a, req, opts)
}
func (e *meteredPolicyHTTPExecutor) ExecuteStream(ctx context.Context, a *auth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.publish(ctx, a, req)
	return e.mockServerStreamingCaptureExecutor.ExecuteStream(ctx, a, req, opts)
}

func TestAPIKeyPolicyHTTPModelAndDailyCap(t *testing.T) {
	testPolicyHTTPDailyCap(t, false)
}

func TestAPIKeyPolicyHTTPRequestCap(t *testing.T) {
	testPolicyHTTPDailyCap(t, true)
}

func testPolicyHTTPDailyCap(t *testing.T, requests bool) {
	t.Helper()
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			const key = "synthetic-control-client"
			const second = "synthetic-control-second-client"
			hash := func(key string) string { digest := sha256.Sum256([]byte(key)); return hex.EncodeToString(digest[:]) }
			cap := int64(5)
			models := []string{"http-control-*"}
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key, second, "unpolicied-key"}, APIKeyPolicies: []config.APIKeyPolicy{
				{KeySHA256: hash(key), AllowedAuths: []string{"*"}, AllowedModels: &models, DailyTokenCap: &cap},
				{KeySHA256: hash(second), AllowedAuths: []string{"*"}, AllowedModels: &models, DailyTokenCap: &cap},
			}}}
			if requests {
				requestCap := int64(1)
				for i := range cfg.APIKeyPolicies {
					cfg.APIKeyPolicies[i].DailyTokenCap = nil
					cfg.APIKeyPolicies[i].DailyRequestCap = &requestCap
				}
			}
			// Statistics defaults off; enforcement cannot depend on the optional sinks.
			server := newTestServerWithConfig(t, cfg)
			executor := &meteredPolicyHTTPExecutor{mockServerStreamingCaptureExecutor: mockServerStreamingCaptureExecutor{cfg: cfg}}
			server.handlers.AuthManager.RegisterExecutor(executor)
			selected := &auth.Auth{ID: "http-controls-auth", FileName: "synthetic.json", Provider: executor.Identifier()}
			if _, err := server.handlers.AuthManager.Register(context.Background(), selected); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(selected.ID, selected.Provider, []*registry.ModelInfo{{ID: "http-control-model"}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(selected.ID) })
			request := func(key, model string) *httptest.ResponseRecorder {
				streamFlag := "false"
				if stream {
					streamFlag = "true"
				}
				req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+model+`","input":[],"stream":`+streamFlag+`}`))
				req.Header.Set("Authorization", "Bearer "+key)
				req.Header.Set("Content-Type", "application/json")
				rr := httptest.NewRecorder()
				server.engine.ServeHTTP(rr, req)
				return rr
			}
			denied := request(key, "denied-unregistered-model")
			if denied.Code != 403 || executor.calls.Load() != 0 {
				t.Fatalf("model selected before denial: %d %s", denied.Code, denied.Body.String())
			}
			first := request(key, "http-control-model")
			if first.Code != 200 || executor.calls.Load() != 1 {
				t.Fatalf("allowed model failed: %d %s", first.Code, first.Body.String())
			}
			capped := request(key, "http-control-model")
			if capped.Code != 429 || executor.calls.Load() != 1 || !strings.Contains(capped.Body.String(), "00:00 UTC") {
				t.Fatalf("recorded cap escaped: %d %s", capped.Code, capped.Body.String())
			}
			other := request(second, "http-control-model")
			if other.Code != 200 || executor.calls.Load() != 2 {
				t.Fatal("one key consumed another key's cap")
			}
			unrestricted := request("unpolicied-key", "http-control-model")
			if unrestricted.Code != 200 || executor.calls.Load() != 3 {
				t.Fatal("unpolicied client changed")
			}
		})
	}
}
