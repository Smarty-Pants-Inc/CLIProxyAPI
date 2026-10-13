package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

const policyClaudeModel = "claude-opus-5-5"

// fakeClaudeUpstream answers /v1/messages with usage input 4 + output 3 = 7.
func fakeClaudeUpstream(t *testing.T, status int, calls *atomic.Int32, last *[]byte, mu *sync.Mutex, cred string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*last = body
		mu.Unlock()
		if got := gjson.GetBytes(body, "model").String(); got != policyClaudeModel {
			t.Errorf("wire model=%q", got)
		}
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization") + r.Header.Get("X-Api-Key"); !strings.HasSuffix(got, cred) {
			t.Errorf("wrong credential: %q want %q", got, cred)
		}
		if status != 200 {
			w.Header().Set("Location", "/other")
			w.WriteHeader(status)
			return
		}
		if gjson.GetBytes(body, "stream").Bool() {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n", policyClaudeModel)
			fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
			fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n")
			fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
			fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":4,\"output_tokens\":3}}\n\n")
			fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"m","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"input_tokens":4,"output_tokens":3}}`, policyClaudeModel)
	}))
}

func registerPolicyClaudeAuths(t *testing.T, server *Server, baseURL string, oauth, disableA bool) {
	t.Helper()
	info := registry.LookupStaticModelInfoByChannel(policyClaudeModel, "claude")
	if info == nil {
		info = &registry.ModelInfo{ID: policyClaudeModel}
	}
	for _, id := range []string{"A", "B"} {
		a := &auth.Auth{ID: id, Provider: "claude", Status: auth.StatusActive, Disabled: disableA && id == "A", Attributes: map[string]string{"api_key": "verified-" + id, "base_url": baseURL}}
		if oauth {
			a.Attributes = map[string]string{"base_url": baseURL}
			a.Metadata = map[string]any{"access_token": "verified-" + id}
		}
		if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{info, {ID: "claude-other"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
}

func policyClaudeConfig(models []string, auths []string, tokenCap, requestCap *int64) *config.Config {
	digest := sha256.Sum256([]byte("test-key"))
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}}, WebsocketAuth: true}
	cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: auths, AllowedModels: &models, DailyRequestCap: requestCap, DailyTokenCap: tokenCap}}
	return cfg
}

func sendPolicied(server *Server, path, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	server.engine.ServeHTTP(rr, req)
	return rr
}

// A policied key reaches Claude on POST /v1/responses and POST /v1/messages,
// only on its allowed auths and models; Claude usage (4+3) feeds the token cap.
func TestKeyPolicyClaude(t *testing.T) {
	for _, tc := range []struct {
		name, path, model    string
		stream, oauth, noCap bool
		disableA             bool
		upstream             int
		tokenCap             int64
		want, second         int
		wantCalls            int32
	}{
		// A cap of 7 is spent by one call (7 tokens), a cap of 8 is not.
		{name: "responses cap spent", path: "/v1/responses", tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "responses cap left", path: "/v1/responses", tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "responses SSE cap spent", path: "/v1/responses", stream: true, tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "responses SSE cap left", path: "/v1/responses", stream: true, tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "messages cap spent", path: "/v1/messages", tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "messages cap left", path: "/v1/messages", tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "messages SSE cap spent", path: "/v1/messages", stream: true, tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "messages SSE cap left", path: "/v1/messages", stream: true, tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "OAuth", path: "/v1/responses", oauth: true, tokenCap: 100, want: 200, wantCalls: 1},
		{name: "model forbidden", path: "/v1/responses", model: "claude-other", tokenCap: 100, want: 403},
		{name: "messages model forbidden", path: "/v1/messages", model: "claude-other", tokenCap: 100, want: 403},
		{name: "only outside auth eligible", path: "/v1/responses", disableA: true, tokenCap: 100, want: 503},
		{name: "redirect", path: "/v1/responses", upstream: 307, tokenCap: 100, want: 503, wantCalls: 1},
		{name: "request cap", path: "/v1/responses", noCap: true, tokenCap: 100, want: 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			var mu sync.Mutex
			var last []byte
			status := tc.upstream
			if status == 0 {
				status = 200
			}
			upstream := fakeClaudeUpstream(t, status, &calls, &last, &mu, "verified-A")
			defer upstream.Close()
			requestCap := int64(10)
			if tc.noCap {
				requestCap = 0
			}
			cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tc.tokenCap, &requestCap)
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			registerPolicyClaudeAuths(t, server, upstream.URL, tc.oauth, tc.disableA)
			model := tc.model
			if model == "" {
				model = policyClaudeModel
			}
			body := fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, model, tc.stream)
			if tc.path == "/v1/messages" {
				body = fmt.Sprintf(`{"model":%q,"max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":%t}`, model, tc.stream)
			}
			rr := sendPolicied(server, tc.path, body)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d: %s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.want == 200 && !strings.Contains(rr.Body.String(), "hi") {
				t.Fatalf("missing upstream content: %s", rr.Body.String())
			}
			if tc.want == 403 && !strings.Contains(rr.Body.String(), "api_key_model_forbidden") {
				t.Fatalf("want api_key_model_forbidden: %s", rr.Body.String())
			}
			if tc.second != 0 {
				if rr = sendPolicied(server, tc.path, body); rr.Code != tc.second {
					t.Fatalf("second status=%d want=%d: %s", rr.Code, tc.second, rr.Body.String())
				}
			}
			if calls.Load() != tc.wantCalls {
				t.Fatalf("upstream calls=%d want=%d", calls.Load(), tc.wantCalls)
			}
		})
	}
}

// TriStar's gateway shape: reasoning.effort xhigh with max_output_tokens 40960.
func TestKeyPolicyClaudeResponsesReasoning(t *testing.T) {
	var calls atomic.Int32
	var mu sync.Mutex
	var last []byte
	upstream := fakeClaudeUpstream(t, 200, &calls, &last, &mu, "verified-A")
	defer upstream.Close()
	tokenCap, requestCap := int64(100), int64(10)
	cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tokenCap, &requestCap)
	server := newTestServerWithConfig(t, cfg)
	server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
	registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
	rr := sendPolicied(server, "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"hello","reasoning":{"effort":"xhigh"},"max_output_tokens":40960}`, policyClaudeModel))
	if rr.Code != 200 {
		t.Fatalf("status=%d: %s", rr.Code, rr.Body.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if got := gjson.GetBytes(last, "max_tokens").Int(); got != 40960 {
		t.Fatalf("max_tokens=%d body=%s", got, last)
	}
	if got := gjson.GetBytes(last, "thinking.budget_tokens").Int(); got != 32768 {
		t.Fatalf("thinking.budget_tokens=%d thinking=%s output_config=%s", got, gjson.GetBytes(last, "thinking").Raw, gjson.GetBytes(last, "output_config").Raw)
	}
}

// With a Claude and a Codex auth both allowed, each model reaches only its own
// provider, whichever auth the policy lists first.
func TestKeyPolicyClaudeCodexSeparation(t *testing.T) {
	const codexModel = "gpt-6.1-sol"
	for _, order := range [][]string{{"C", "A"}, {"A", "C"}} {
		for _, model := range []string{policyClaudeModel, codexModel} {
			t.Run(strings.Join(order, "")+"/"+model, func(t *testing.T) {
				var claudeCalls, codexCalls atomic.Int32
				var mu sync.Mutex
				var last []byte
				claudeUp := fakeClaudeUpstream(t, 200, &claudeCalls, &last, &mu, "verified-A")
				defer claudeUp.Close()
				codexUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					codexCalls.Add(1)
					if r.Header.Get("Authorization") != "Bearer verified-C" {
						t.Errorf("wrong codex credential: %q", r.Header.Get("Authorization"))
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":%q,\"output\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":3,\"total_tokens\":7}}}\n\n", codexModel)
				}))
				defer codexUp.Close()
				tokenCap, requestCap := int64(100), int64(10)
				cfg := policyClaudeConfig([]string{policyClaudeModel, codexModel}, order, &tokenCap, &requestCap)
				server := newTestServerWithConfig(t, cfg)
				server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
				server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
				registerPolicyClaudeAuths(t, server, claudeUp.URL, false, false)
				c := &auth.Auth{ID: "C", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "verified-C", "base_url": codexUp.URL}}
				if _, err := server.handlers.AuthManager.Register(context.Background(), c); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient("C", "codex", []*registry.ModelInfo{{ID: codexModel}})
				defer registry.GetGlobalRegistry().UnregisterClient("C")
				rr := sendPolicied(server, "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"hello"}`, model))
				if rr.Code != 200 {
					t.Fatalf("status=%d: %s", rr.Code, rr.Body.String())
				}
				wantClaude, wantCodex := int32(1), int32(0)
				if model == codexModel {
					wantClaude, wantCodex = 0, 1
				}
				if claudeCalls.Load() != wantClaude || codexCalls.Load() != wantCodex {
					t.Fatalf("claude calls=%d codex calls=%d", claudeCalls.Load(), codexCalls.Load())
				}
			})
		}
	}
}
