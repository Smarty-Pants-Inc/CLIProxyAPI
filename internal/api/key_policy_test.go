package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

type policyUsagePlugin struct{ calls atomic.Int32 }

func (p *policyUsagePlugin) HandleUsage(context.Context, usage.Record) { p.calls.Add(1) }

type policyUsageSink struct{ records chan usage.Record }

func (p *policyUsageSink) BuiltinUsageSink() {}
func (p *policyUsageSink) HandleUsage(_ context.Context, r usage.Record) {
	if r.Provider == "codex" {
		p.records <- r
	}
}

func TestKeyPolicyHTTP(t *testing.T) {
	for _, tc := range []struct {
		name, model, allowed, path string
		disabled, legacy, stream   bool
		cap                        int64
		upstream, want             int
	}{
		{name: "OAuth", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "compressed", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "partial usage", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "input only", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "output only", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "input only SSE", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "output only SSE", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "mixed aliases", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "mixed aliases SSE", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "token meter", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "request meter", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 1},
		{name: "allowed", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "SSE", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "usage reload", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "model", model: "other", allowed: "A", upstream: 200, want: 403, cap: 10},
		{name: "exact IDs", model: "gpt-6.1-sol", allowed: "a", upstream: 200, want: 503, cap: 10},
		{name: "no eligible", model: "gpt-6.1-sol", allowed: "A", disabled: true, upstream: 200, want: 503, cap: 10},
		{name: "no retry", model: "gpt-6.1-sol", allowed: "A", upstream: 503, want: 503, cap: 10},
		{name: "redirect", model: "gpt-6.1-sol", allowed: "A", upstream: 307, want: 503, cap: 10},
		{name: "zero cap", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 429},
		{name: "legacy", model: "gpt-6.1-sol", allowed: "a", legacy: true, upstream: 200, want: 200, cap: 10},
		{name: "unsupported", model: "gpt-6.1-sol", allowed: "A", path: "/v1/chat/completions", upstream: 200, want: 503, cap: 10},
		{name: "socket Responses", allowed: "A", want: 503, cap: 10},
		{name: "socket Realtime", allowed: "A", path: "/v1/realtime", want: 503, cap: 10},
		{name: "socket sideband", allowed: "A", path: "/v1/live/call", want: 503, cap: 10},
		{name: "restricted hangup", allowed: "A", path: "/v1/realtime/calls/call/hangup", want: 503, cap: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var server *Server
			plugin := &policyUsagePlugin{}
			sink := &policyUsageSink{records: make(chan usage.Record, 8)}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if tc.name == "usage reload" {
					next := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}}, WebsocketAuth: true}
					next.Plugins.Enabled = true
					server.handlers.AuthManager.SetConfig(next)
					server.UpdateClients(next)
					usage.RegisterNamedPlugin(t.Name()+" external", plugin)
					usage.RegisterNamedPlugin(t.Name()+" builtin", sink)
					t.Cleanup(func() {
						usage.RegisterNamedPlugin(t.Name()+" builtin", &policyUsagePlugin{})
						usage.RegisterNamedPlugin(t.Name()+" external", &policyUsagePlugin{})
					})
				}
				body, _ := io.ReadAll(r.Body)
				var wire struct {
					Model string `json:"model"`
				}
				if err := json.Unmarshal(body, &wire); err != nil || wire.Model != "gpt-6.1-sol" {
					t.Errorf("wire model=%q err=%v", wire.Model, err)
				}
				if r.Header.Get("Authorization") != "Bearer verified-A" {
					t.Errorf("wrong credential: %s", r.Header.Get("Authorization"))
				}
				if tc.name == "OAuth" && r.Header.Get("Chatgpt-Account-Id") != "account-A" {
					t.Errorf("wrong account: %s", r.Header.Get("Chatgpt-Account-Id"))
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Location", "/other")
				w.WriteHeader(tc.upstream)
				fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6.1-sol\"}}\n\n")
				usage := `{"input_tokens":4,"output_tokens":3,"total_tokens":7}`
				if tc.name == "partial usage" {
					usage = `{"input_tokens":1,"total_tokens":10}`
				} else if strings.HasPrefix(tc.name, "input only") {
					usage = `{"input_tokens":1}`
				} else if strings.HasPrefix(tc.name, "output only") {
					usage = `{"output_tokens":1}`
				} else if strings.HasPrefix(tc.name, "mixed aliases") {
					// F31: canonical counts total 200; conflicting legacy aliases total 2.
					usage = `{"input_tokens":100,"output_tokens":100,"prompt_tokens":1,"completion_tokens":1}`
				}
				fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6.1-sol\",\"output\":[],\"usage\":%s}}\n\n", usage)
			}))
			defer upstream.Close()
			digest := sha256.Sum256([]byte("test-key"))
			models := []string{"gpt-6.1-sol"}
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}}, WebsocketAuth: true}
			if !tc.legacy {
				cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{tc.allowed}, AllowedModels: &models, DailyRequestCap: &tc.cap}}
			}
			if tc.name == "partial usage" || strings.Contains(tc.name, "only") || strings.HasPrefix(tc.name, "mixed aliases") {
				cfg.APIKeyPolicies[0].DailyTokenCap = &tc.cap
			}
			if tc.name == "token meter" {
				limit := int64(1)
				cfg.APIKeyPolicies[0].DailyTokenCap = &limit
			}
			server = newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
			for _, id := range []string{"A", "B"} {
				a := &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Disabled: tc.disabled && id == "A", Attributes: map[string]string{"api_key": "verified-" + id, "base_url": upstream.URL}}
				if tc.name == "OAuth" {
					delete(a.Attributes, "api_key")
					a.Metadata = map[string]any{"access_token": "verified-" + id, "account_id": "account-" + id}
				}
				if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
			}
			path := tc.path
			if path == "" {
				path = "/v1/responses"
			}
			rr := httptest.NewRecorder()
			method := "POST"
			if strings.HasPrefix(tc.name, "socket") {
				method = "GET"
			}
			req := httptest.NewRequest(method, path, strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, tc.model, tc.stream)))
			if tc.name == "compressed" {
				body, _ := io.ReadAll(req.Body)
				enc, _ := zstd.NewWriter(nil)
				req.Body = io.NopCloser(bytes.NewReader(enc.EncodeAll(body, nil)))
				enc.Close()
				req.Header.Set("Content-Encoding", "zstd")
			}
			req.Header.Set("Authorization", "Bearer test-key")
			server.engine.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d: %s", rr.Code, tc.want, rr.Body.String())
			}
			wantCalls := int32(0)
			if tc.want == 200 || tc.name == "no retry" || tc.name == "redirect" {
				wantCalls = 1
			}
			if tc.name == "token meter" || tc.name == "request meter" || tc.name == "partial usage" || strings.Contains(tc.name, "only") || strings.HasPrefix(tc.name, "mixed aliases") {
				rr = httptest.NewRecorder()
				req = httptest.NewRequest("POST", path, strings.NewReader(`{"model":"gpt-6.1-sol","input":"hello"}`))
				req.Header.Set("Authorization", "Bearer test-key")
				server.engine.ServeHTTP(rr, req)
				if rr.Code != 429 {
					t.Fatalf("second request=%d: %s", rr.Code, rr.Body.String())
				}
			}
			if tc.name == "usage reload" {
				r := <-sink.records
				if r.APIKey == "test-key" || plugin.calls.Load() != 0 {
					t.Fatalf("restricted reload leaked usage: key=%q external calls=%d", r.APIKey, plugin.calls.Load())
				}
			}
			if calls.Load() != wantCalls {
				t.Fatalf("upstream calls=%d want=%d", calls.Load(), wantCalls)
			}
		})
	}
}
