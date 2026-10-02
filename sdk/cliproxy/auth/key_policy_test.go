package auth

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestKeyPolicyCaps(t *testing.T) {
	for _, tc := range []struct {
		name             string
		requests, tokens *int64
		want             int32
	}{
		{"requests", policyInt(7), nil, 7}, {"tokens", nil, policyInt(10), 2}, {"zero", nil, policyInt(0), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			m.SetConfig(&config.Config{})
			now := time.Date(2026, 10, 1, 23, 59, 59, 0, time.UTC)
			m.keyPolicyNow = func() time.Time { return now }
			p := []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), DailyRequestCap: tc.requests, DailyTokenCap: tc.tokens}}
			var accepted atomic.Int32
			var wg sync.WaitGroup
			for i := 0; i < 30; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					ctx, done, err := m.BeginKeyPolicy(context.Background(), p, "model")
					if err != nil {
						return
					}
					accepted.Add(1)
					usage.PublishRecord(ctx, usage.Record{Detail: usage.Detail{InputTokens: 4, OutputTokens: 3}})
					done()
				}()
			}
			wg.Wait()
			if accepted.Load() != tc.want {
				t.Fatalf("accepted=%d want=%d", accepted.Load(), tc.want)
			}
			// Tokens total 14 for cap 10: one operation (7 tokens), not 30, bounds overshoot.
			now = now.Add(time.Second)
			_, done, err := m.BeginKeyPolicy(context.Background(), p, "model")
			if tc.want > 0 {
				if err != nil {
					t.Fatal("UTC reset:", err)
				}
				done()
			} else if err == nil {
				done()
				t.Fatal("zero cap admitted")
			}
		})
	}
}
func policyInt(v int64) *int64 { return &v }

func TestKeyPolicyAdmissionFloorAndWireFence(t *testing.T) {
	for _, change := range []string{"relax", "replacement", "provider", "model", "replay", "tighten", "missing usage"} {
		t.Run(change, func(t *testing.T) {
			m := NewManager(nil, nil, nil)
			models := []string{"model"}
			floor := config.APIKeyPolicy{KeySHA256: keyDigest("key"), AllowedAuths: []string{"A"}, AllowedModels: &models, DailyRequestCap: policyInt(1), DailyTokenCap: policyInt(10)}
			m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{floor}}})
			ctx, done, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{{KeySHA256: floor.KeySHA256, AllowedAuths: []string{"A", "B"}}}, "model")
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Set("userApiKey", "key")
			if !m.MissingKeyPolicy(context.WithValue(context.Background(), "gin", c)) {
				t.Fatal("retained socket without admission accepted")
			}
			m.SetConfig(&config.Config{}) // relaxation cannot erase policy introduced at operation admission
			models[0] = "other"
			floor.AllowedAuths[0] = "B"
			*floor.DailyRequestCap = 100
			a := &Auth{ID: "A", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"api_key": "A-token"}, Metadata: map[string]any{"nested": map[string]any{"secret": "A"}}}
			_, _ = m.Register(context.Background(), a)
			m.RegisterExecutor(&countingRefreshExecutor{id: "codex"})
			registry.GetGlobalRegistry().RegisterClient("A", "codex", []*registry.ModelInfo{{ID: "model"}})
			defer registry.GetGlobalRegistry().UnregisterClient("A")
			op := KeyPolicyFromContext(ctx)
			if op.allows(&Auth{ID: "B"}) {
				t.Fatal("admission floor erased")
			}
			if _, _, err := op.selectExecutor(ex.Request{Model: "model"}, ex.Options{}); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "http://example/responses", strings.NewReader(`{"model":"model"}`)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer A-token")
			switch change {
			case "replacement":
				a.Metadata["nested"].(map[string]any)["secret"] = "B"
				_, _ = m.Register(context.Background(), a)
			case "provider":
				a.Provider = "xai"
				_, _ = m.Register(context.Background(), a)
			case "model":
				req.Body = httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"other"}`)).Body
			case "tighten":
				m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), AllowedAuths: []string{"A"}, DailyRequestCap: policyInt(0)}}}})
			}
			err = CheckKeyPolicySend(req)
			rejected := change == "replacement" || change == "provider" || change == "model" || change == "tighten"
			if (err != nil) != rejected {
				t.Fatalf("wire check=%v rejected=%t", err, rejected)
			}
			if change == "replay" && CheckKeyPolicySend(req) == nil {
				t.Fatal("second send admitted")
			}
			if change == "missing usage" {
				done()
				if _, next, err := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), DailyTokenCap: policyInt(10)}}, "model"); err == nil {
					next()
					t.Fatal("unmetered send admitted another operation")
				}
			}
		})
	}
}
