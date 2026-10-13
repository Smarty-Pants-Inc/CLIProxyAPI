package api

import (
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

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// A policied key reaches Claude through POST /v1/messages, only on its allowed
// auths and models, and Claude usage (input + output) feeds the daily token cap.
func TestKeyPolicyClaudeMessages(t *testing.T) {
	const model = "claude-sonnet-4-6"
	for _, tc := range []struct {
		name, model    string
		stream, oauth  bool
		disableA       bool
		tokenCap       int64
		want, second   int
		wantCalls      int32
		secondRequests bool
	}{
		// Usage 4+3=7: a cap of 7 is spent by one call, a cap of 8 is not.
		{name: "non-stream cap spent", model: model, tokenCap: 7, want: 200, second: 429, wantCalls: 1, secondRequests: true},
		{name: "non-stream cap left", model: model, tokenCap: 8, want: 200, second: 200, wantCalls: 2, secondRequests: true},
		{name: "stream cap spent", model: model, stream: true, tokenCap: 7, want: 200, second: 429, wantCalls: 1, secondRequests: true},
		{name: "stream cap left", model: model, stream: true, tokenCap: 8, want: 200, second: 200, wantCalls: 2, secondRequests: true},
		{name: "OAuth", model: model, oauth: true, tokenCap: 100, want: 200, wantCalls: 1},
		{name: "model forbidden", model: "claude-opus-4-6", tokenCap: 100, want: 403},
		{name: "only disallowed auth eligible", model: model, disableA: true, tokenCap: 100, want: 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				body, _ := io.ReadAll(r.Body)
				var wire struct {
					Model string `json:"model"`
				}
				if err := json.Unmarshal(body, &wire); err != nil || wire.Model != model {
					t.Errorf("wire model=%q err=%v", wire.Model, err)
				}
				if r.URL.Path != "/v1/messages" {
					t.Errorf("path=%s", r.URL.Path)
				}
				if got := r.Header.Get("Authorization") + r.Header.Get("X-Api-Key"); !strings.HasSuffix(got, "verified-A") {
					t.Errorf("wrong credential: %q", got)
				}
				if tc.stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n", model)
					fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
					fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n")
					fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
					fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}\n\n")
					fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"id":"m","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":4,"output_tokens":3}}`, model)
			}))
			defer upstream.Close()

			digest := sha256.Sum256([]byte("test-key"))
			models := []string{model}
			requestCap := int64(10)
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}}, WebsocketAuth: true}
			cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"A"}, AllowedModels: &models, DailyRequestCap: &requestCap, DailyTokenCap: &tc.tokenCap}}
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			for _, id := range []string{"A", "B"} {
				a := &auth.Auth{ID: id, Provider: "claude", Status: auth.StatusActive, Disabled: tc.disableA && id == "A", Attributes: map[string]string{"api_key": "verified-" + id, "base_url": upstream.URL}}
				if tc.oauth {
					a.Attributes = map[string]string{"base_url": upstream.URL}
					a.Metadata = map[string]any{"access_token": "verified-" + id}
				}
				if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}, {ID: "claude-opus-4-6"}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
			}
			send := func() *httptest.ResponseRecorder {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(fmt.Sprintf(`{"model":%q,"max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":%t}`, tc.model, tc.stream)))
				req.Header.Set("Authorization", "Bearer test-key")
				server.engine.ServeHTTP(rr, req)
				return rr
			}
			rr := send()
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d: %s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.want == 200 && !strings.Contains(rr.Body.String(), "hi") {
				t.Fatalf("missing upstream content: %s", rr.Body.String())
			}
			if tc.want == 403 && !strings.Contains(rr.Body.String(), "api_key_model_forbidden") {
				t.Fatalf("want api_key_model_forbidden: %s", rr.Body.String())
			}
			if tc.secondRequests {
				if rr = send(); rr.Code != tc.second {
					t.Fatalf("second status=%d want=%d: %s", rr.Code, tc.second, rr.Body.String())
				}
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("upstream calls=%d want=%d", calls.Load(), tc.wantCalls)
			}
		})
	}
}
