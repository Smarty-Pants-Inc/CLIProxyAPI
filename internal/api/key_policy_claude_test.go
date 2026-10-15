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

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
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
		// CheckKeyPolicySend already binds the wire model to the admitted one.
		model := gjson.GetBytes(body, "model").String()
		if !strings.HasPrefix(model, "claude-") {
			t.Errorf("wire model=%q", model)
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
}

func registerPolicyClaudeAuths(t *testing.T, server *Server, baseURL string, oauth, disableA bool) {
	t.Helper()
	infos := []*registry.ModelInfo{{ID: "claude-other"}}
	for _, id := range []string{policyClaudeModel, "claude-sonnet-5-5", "claude-sonnet-4-5-20250929"} {
		info := registry.LookupStaticModelInfoByChannel(id, "claude")
		if info == nil {
			t.Fatalf("no static model %s", id)
		}
		infos = append(infos, info)
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
		registry.GetGlobalRegistry().RegisterClient(id, "claude", infos)
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}
}

func policyClaudeConfig(models []string, auths []string, tokenCap, requestCap *int64) *config.Config {
	digest := sha256.Sum256([]byte("test-key"))
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}}, WebsocketAuth: true}
	cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: auths, AllowedModels: &models, DailyRequestCap: requestCap, DailyTokenCap: tokenCap}}
	return cfg
}

// policyBody builds a minimal request body in the endpoint's own format.
func policyBody(path, model string, stream bool) string {
	switch path {
	case "/v1/messages":
		return fmt.Sprintf(`{"model":%q,"max_tokens":16,"messages":[{"role":"user","content":"hello"}],"stream":%t}`, model, stream)
	case "/v1/chat/completions":
		return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}],"stream":%t}`, model, stream)
	}
	return fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, model, stream)
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
		// TriStar's node-gateway calls POST /v1/chat/completions.
		{name: "chat cap spent", path: "/v1/chat/completions", tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "chat cap left", path: "/v1/chat/completions", tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "chat SSE cap spent", path: "/v1/chat/completions", stream: true, tokenCap: 7, want: 200, second: 429, wantCalls: 1},
		{name: "chat SSE cap left", path: "/v1/chat/completions", stream: true, tokenCap: 8, want: 200, second: 200, wantCalls: 2},
		{name: "chat model forbidden", path: "/v1/chat/completions", model: "claude-other", tokenCap: 100, want: 403},
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
			body := policyBody(tc.path, model, tc.stream)
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

// TriStar's gateway shape: /v1/responses with reasoning.effort and
// max_output_tokens 40960. Policy admission must not change the thinking
// translation, so each case also compares against an unrestricted key.
// Models with catalog thinking levels (claude-opus-5-5) get adaptive thinking
// with output_config.effort; models without levels get budget_tokens.
func TestKeyPolicyClaudeResponsesReasoning(t *testing.T) {
	for _, tc := range []struct {
		model, effort, wantType, wantEffort string
		wantBudget                          int64
	}{
		// Main's newer catalog supports xhigh directly; policy admission must preserve it.
		{model: policyClaudeModel, effort: "xhigh", wantType: "adaptive", wantEffort: "xhigh"},
		{model: policyClaudeModel, effort: "medium", wantType: "adaptive", wantEffort: "medium"},
		{model: "claude-sonnet-4-5-20250929", effort: "xhigh", wantType: "enabled", wantBudget: 32768},
	} {
		t.Run(tc.model+"/"+tc.effort, func(t *testing.T) {
			got := map[bool]string{}
			for _, policied := range []bool{true, false} {
				var calls atomic.Int32
				var mu sync.Mutex
				var last []byte
				upstream := fakeClaudeUpstream(t, 200, &calls, &last, &mu, "verified-A")
				defer upstream.Close()
				tokenCap, requestCap := int64(100), int64(10)
				cfg := policyClaudeConfig([]string{tc.model}, []string{"A"}, &tokenCap, &requestCap)
				if !policied {
					cfg.APIKeyPolicies = nil
				}
				server := newTestServerWithConfig(t, cfg)
				server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
				registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
				rr := sendPolicied(server, "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"hello","reasoning":{"effort":%q},"max_output_tokens":40960}`, tc.model, tc.effort))
				if rr.Code != 200 {
					t.Fatalf("policied=%v status=%d: %s", policied, rr.Code, rr.Body.String())
				}
				mu.Lock()
				body := last
				mu.Unlock()
				if n := gjson.GetBytes(body, "max_tokens").Int(); n != 40960 {
					t.Fatalf("policied=%v max_tokens=%d", policied, n)
				}
				if v := gjson.GetBytes(body, "thinking.type").String(); v != tc.wantType {
					t.Fatalf("policied=%v thinking.type=%q: %s", policied, v, body)
				}
				if v := gjson.GetBytes(body, "output_config.effort").String(); v != tc.wantEffort {
					t.Fatalf("policied=%v output_config.effort=%q", policied, v)
				}
				budget := gjson.GetBytes(body, "thinking.budget_tokens")
				if tc.wantBudget == 0 && budget.Exists() || tc.wantBudget != 0 && budget.Int() != tc.wantBudget {
					t.Fatalf("policied=%v thinking.budget_tokens=%s", policied, budget.Raw)
				}
				got[policied] = gjson.GetBytes(body, "max_tokens").Raw + gjson.GetBytes(body, "thinking").Raw + gjson.GetBytes(body, "output_config").Raw
			}
			if got[true] != got[false] {
				t.Fatalf("policied upstream %s differs from unrestricted %s", got[true], got[false])
			}
			t.Logf("upstream max_tokens+thinking+output_config: %s", got[true])
		})
	}
}

// net-lead's policy shape: only two Claude models and one Claude auth. A second
// Claude auth and a Codex auth that both claim the model stay unused, and a
// Codex model is forbidden.
func TestKeyPolicyClaudeSingleAuthPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, model string
		disableA    bool
		want        int
		wantCalls   int32
	}{
		{name: "opus on A", model: policyClaudeModel, want: 200, wantCalls: 1},
		{name: "sonnet on A", model: "claude-sonnet-5-5", want: 200, wantCalls: 1},
		{name: "A unavailable", model: policyClaudeModel, disableA: true, want: 503},
		{name: "codex model", model: "gpt-6-luna", want: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls, codexCalls atomic.Int32
			var mu sync.Mutex
			var last []byte
			upstream := fakeClaudeUpstream(t, 200, &calls, &last, &mu, "verified-A")
			defer upstream.Close()
			codexUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				codexCalls.Add(1)
				w.WriteHeader(500)
			}))
			defer codexUp.Close()
			tokenCap, requestCap := int64(100), int64(10)
			cfg := policyClaudeConfig([]string{policyClaudeModel, "claude-sonnet-5-5"}, []string{"A"}, &tokenCap, &requestCap)
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
			registerPolicyClaudeAuths(t, server, upstream.URL, false, tc.disableA)
			c := &auth.Auth{ID: "C", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "verified-C", "base_url": codexUp.URL}}
			if _, err := server.handlers.AuthManager.Register(context.Background(), c); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient("C", "codex", []*registry.ModelInfo{{ID: "gpt-6-luna"}, {ID: policyClaudeModel}, {ID: "claude-sonnet-5-5"}})
			defer registry.GetGlobalRegistry().UnregisterClient("C")
			rr := sendPolicied(server, "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"hello"}`, tc.model))
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d: %s", rr.Code, tc.want, rr.Body.String())
			}
			if tc.want == 403 && !strings.Contains(rr.Body.String(), "api_key_model_forbidden") {
				t.Fatalf("want api_key_model_forbidden: %s", rr.Body.String())
			}
			if calls.Load() != tc.wantCalls || codexCalls.Load() != 0 {
				t.Fatalf("claude calls=%d want=%d codex calls=%d", calls.Load(), tc.wantCalls, codexCalls.Load())
			}
		})
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
