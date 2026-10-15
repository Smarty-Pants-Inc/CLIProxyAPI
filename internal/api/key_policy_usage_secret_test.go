package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/redisqueue"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

type secretUsageSink struct{ records chan usage.Record }

func (s *secretUsageSink) BuiltinUsageSink() {}
func (s *secretUsageSink) HandleUsage(_ context.Context, r usage.Record) {
	select {
	case s.records <- r:
	default:
	}
}

// An upstream API-key credential selected for a policied key must not appear
// in any usage record field or in the Redis usage queue payload.
func TestKeyPolicyUsageNeverCarriesUpstreamAPIKey(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			const secret = "sk-raw-upstream-SECRET-7f3a9c"
			var calls atomic.Int32
			var mu sync.Mutex
			var last []byte
			model := policyClaudeModel
			var upstream *httptest.Server
			if provider == "claude" {
				upstream = fakeClaudeUpstream(t, 200, &calls, &last, &mu, secret)
			} else {
				model = "gpt-6.1-sol"
				upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Authorization") != "Bearer "+secret {
						t.Errorf("wrong codex credential")
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":%q,\"output\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":3,\"total_tokens\":7}}}\n\n", model)
				}))
			}
			defer upstream.Close()

			tokenCap, requestCap := int64(100), int64(10)
			cfg := policyClaudeConfig([]string{model}, []string{"K"}, &tokenCap, &requestCap)
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewClaudeExecutor(cfg))
			server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
			a := &auth.Auth{ID: "K", Provider: provider, Status: auth.StatusActive, Attributes: map[string]string{"api_key": secret, "base_url": upstream.URL}}
			if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			info := registry.LookupStaticModelInfoByChannel(model, provider)
			if info == nil {
				info = &registry.ModelInfo{ID: model}
			}
			registry.GetGlobalRegistry().RegisterClient("K", provider, []*registry.ModelInfo{info})
			defer registry.GetGlobalRegistry().UnregisterClient("K")

			sink := &secretUsageSink{records: make(chan usage.Record, 8)}
			usage.RegisterNamedPlugin(t.Name()+" sink", sink)
			t.Cleanup(func() { usage.RegisterNamedPlugin(t.Name()+" sink", &policyUsagePlugin{}) })
			redisqueue.SetEnabled(true)
			t.Cleanup(func() { redisqueue.SetEnabled(false) })
			queued, unsubscribe := redisqueue.SubscribeUsage()
			defer unsubscribe()

			rr := sendPolicied(server, "/v1/responses", fmt.Sprintf(`{"model":%q,"input":"hello"}`, model))
			if rr.Code != 200 {
				t.Fatalf("status=%d: %s", rr.Code, rr.Body.String())
			}
			var record usage.Record
			select {
			case record = <-sink.records:
			case <-time.After(5 * time.Second):
				t.Fatal("no usage record")
			}
			var payload []byte
			select {
			case payload = <-queued:
			case <-time.After(5 * time.Second):
				t.Fatal("no redis usage payload")
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for name, text := range map[string]string{"record JSON": string(encoded), "record fields": fmt.Sprintf("%+v", record), "redis payload": string(payload)} {
				if strings.Contains(text, secret) {
					t.Fatalf("%s carries the upstream API key: %s", name, text)
				}
			}
			if record.Detail.InputTokens != 4 {
				t.Fatalf("usage record lost its tokens: %+v", record.Detail)
			}
		})
	}
}
