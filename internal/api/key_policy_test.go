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
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

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
		{name: "token meter", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "request meter", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 1},
		{name: "allowed", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10},
		{name: "SSE", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 200, cap: 10, stream: true},
		{name: "model", model: "other", allowed: "A", upstream: 200, want: 403, cap: 10},
		{name: "exact IDs", model: "gpt-6.1-sol", allowed: "a", upstream: 200, want: 503, cap: 10},
		{name: "no eligible", model: "gpt-6.1-sol", allowed: "A", disabled: true, upstream: 200, want: 503, cap: 10},
		{name: "no retry", model: "gpt-6.1-sol", allowed: "A", upstream: 503, want: 503, cap: 10},
		{name: "redirect", model: "gpt-6.1-sol", allowed: "A", upstream: 307, want: 503, cap: 10},
		{name: "zero cap", model: "gpt-6.1-sol", allowed: "A", upstream: 200, want: 429},
		{name: "legacy", model: "gpt-6.1-sol", allowed: "a", legacy: true, upstream: 200, want: 200, cap: 10},
		{name: "unsupported", model: "gpt-6.1-sol", allowed: "A", path: "/v1/chat/completions", upstream: 200, want: 503, cap: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
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
			if tc.name == "partial usage" {
				cfg.APIKeyPolicies[0].DailyTokenCap = &tc.cap
			}
			if tc.name == "token meter" {
				limit := int64(1)
				cfg.APIKeyPolicies[0].DailyTokenCap = &limit
			}
			server := newTestServerWithConfig(t, cfg)
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
			req := httptest.NewRequest("POST", path, strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, tc.model, tc.stream)))
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
			if tc.name == "token meter" || tc.name == "request meter" || tc.name == "partial usage" {
				rr = httptest.NewRecorder()
				req = httptest.NewRequest("POST", path, strings.NewReader(`{"model":"gpt-6.1-sol","input":"hello"}`))
				req.Header.Set("Authorization", "Bearer test-key")
				server.engine.ServeHTTP(rr, req)
				if rr.Code != 429 {
					t.Fatalf("second request=%d: %s", rr.Code, rr.Body.String())
				}
			}
			if calls.Load() != wantCalls {
				t.Fatalf("upstream calls=%d want=%d", calls.Load(), wantCalls)
			}
		})
	}
}
