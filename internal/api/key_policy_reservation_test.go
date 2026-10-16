package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
)

// The real policy/handler/translator/executor/HTTP path must stop a large request
// with one token left, for every supported protocol and delivery mode.
func TestKeyPolicyClaudeReservationNearCap(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/responses", "/v1/chat/completions"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", path, stream), func(t *testing.T) {
				var calls atomic.Int32
				var mu sync.Mutex
				var last []byte
				upstream := fakeClaudeUpstream(t, 200, &calls, &last, &mu, "verified-A")
				defer upstream.Close()
				tokenCap, requestCap := int64(1000000), int64(10)
				cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tokenCap, &requestCap)
				server := newTestServerWithConfig(t, cfg)
				server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
				registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
				// Seed prior trusted usage so a normally usable daily cap has
				// exactly one token left before the HTTP request under test.
				manager := server.handlers.AuthManager
				ctx, done, err := manager.BeginKeyPolicy(context.Background(), manager.KeyPolicies("test-key"), policyClaudeModel)
				if err != nil {
					t.Fatal(err)
				}
				usage.PublishRecord(ctx, usage.Record{Detail: usage.Detail{InputTokens: tokenCap - 1}})
				done()
				body := fmt.Sprintf(`{"model":%q,"input":"large request","max_output_tokens":40960,"stream":%t}`, policyClaudeModel, stream)
				if path == "/v1/messages" {
					body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"large request"}],"max_tokens":40960,"stream":%t}`, policyClaudeModel, stream)
				}
				if path == "/v1/chat/completions" {
					body = fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"large request"}],"max_completion_tokens":40960,"stream":%t}`, policyClaudeModel, stream)
				}
				rr := sendPolicied(server, path, body)
				if rr.Code != http.StatusTooManyRequests || !strings.Contains(rr.Body.String(), "api_key_daily_token_cap") {
					t.Fatalf("near-cap status=%d: %s", rr.Code, rr.Body.String())
				}
				if calls.Load() != 0 {
					t.Fatalf("large request reached upstream: calls=%d want 0", calls.Load())
				}
			})
		}
	}
}

func TestKeyPolicyClaudeReservationErrorRecovery(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"m","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"recovered"}],"stop_reason":"end_turn","usage":{"input_tokens":4,"output_tokens":3}}`, policyClaudeModel)
	}))
	defer upstream.Close()
	tokenCap, requestCap := int64(1000000), int64(2)
	cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tokenCap, &requestCap)
	server := newTestServerWithConfig(t, cfg)
	server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
	registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
	body := policyBody("/v1/messages", policyClaudeModel, false)
	if rr := sendPolicied(server, "/v1/messages", body); rr.Code != 503 {
		t.Fatalf("failed upstream=%d: %s", rr.Code, rr.Body.String())
	}
	if rr := sendPolicied(server, "/v1/messages", body); rr.Code != 200 || !strings.Contains(rr.Body.String(), "recovered") {
		t.Fatalf("reservation retained after error=%d: %s", rr.Code, rr.Body.String())
	}
	// Errors still consume a request, as before: the third request hits that cap.
	if rr := sendPolicied(server, "/v1/messages", body); rr.Code != 429 || !strings.Contains(rr.Body.String(), "api_key_daily_request_cap") {
		t.Fatalf("request counting changed=%d: %s", rr.Code, rr.Body.String())
	}
	if calls.Load() != 2 {
		t.Fatalf("upstream calls=%d want 2", calls.Load())
	}
}

func TestKeyPolicyClaudeReservationFinalPayload(t *testing.T) {
	for _, limit := range []int{16, 20000} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			var calls atomic.Int32
			var mu sync.Mutex
			var last []byte
			upstream := fakeClaudeUpstream(t, 200, &calls, &last, &mu, "verified-A")
			defer upstream.Close()
			tokenCap, requestCap := int64(10000), int64(10)
			cfg := policyClaudeConfig([]string{policyClaudeModel}, []string{"A"}, &tokenCap, &requestCap)
			cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: policyClaudeModel}}, Params: map[string]any{"max_tokens": limit}}}
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			registerPolicyClaudeAuths(t, server, upstream.URL, false, false)
			body := fmt.Sprintf(`{"model":%q,"max_tokens":100000,"messages":[{"role":"user","content":"hello"}]}`, policyClaudeModel)
			rr := sendPolicied(server, "/v1/messages", body)
			if limit == 20000 {
				if rr.Code != 429 || calls.Load() != 0 {
					t.Fatalf("final output limit not fenced: status=%d calls=%d", rr.Code, calls.Load())
				}
			} else {
				if rr.Code != 200 || calls.Load() != 1 {
					t.Fatalf("final lower limit refused: status=%d calls=%d: %s", rr.Code, calls.Load(), rr.Body.String())
				}
				mu.Lock()
				defer mu.Unlock()
				if got := gjson.GetBytes(last, "max_tokens").Int(); got != 16 {
					t.Fatalf("payload rule overwritten: %d", got)
				}
			}
		})
	}
}
