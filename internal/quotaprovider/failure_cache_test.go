package quotaprovider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestOAuthConcurrentFailureExpiresToSuccess(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				_, _ = io.WriteString(w, fixture[provider])
			}))
			defer server.Close()
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
			})
			now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
			p.now = func() time.Time { return now }
			var wg sync.WaitGroup
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					response, err := p.FetchQuota(context.Background(), request(provider, "one"))
					if err != nil || response.Status != "unknown" || len(response.Groups) != 0 {
						t.Error("failure not unknown")
					}
				}()
			}
			wg.Wait()
			if calls.Load() != 1 {
				t.Fatalf("failure generated %d upstream calls", calls.Load())
			}
			now = now.Add(cacheTTL)
			if response := fetch(t, p, request(provider, "one")); response.Status != "known" {
				t.Fatal("expired failure did not recover")
			}
			if calls.Load() != 2 {
				t.Fatal("wrong calls after recovery")
			}
			now = now.Add(cacheTTL)
			// A later failure must replace a prior success, never return stale numeric quota.
			p.resolve = func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) { return Credential{}, nil }
			assertUnknown(t, fetch(t, p, request(provider, "one")))
		})
	}
}

func TestCodexInvalidWindowsUnknown(t *testing.T) {
	for _, body := range []string{
		`{"rate_limit":{"primary_window":{"used_percent":null,"reset_at":1791334800,"limit_window_seconds":18000}}}`,
		`{"rate_limit":{"primary_window":{"used_percent":-1,"reset_at":1791334800,"limit_window_seconds":18000}}}`,
		`{"rate_limit":{"primary_window":{"used_percent":101,"reset_at":1791334800,"limit_window_seconds":18000}}}`,
		`{"rate_limit":{"primary_window":{"used_percent":0,"reset_at":null,"limit_window_seconds":18000}}}`,
		`{"rate_limit":{"primary_window":{"used_percent":0,"reset_at":1791334800}}}`,
		`{"rate_limit":{"primary_window":{"used_percent":0,"reset_at":1791334800,"limit_window_seconds":123}}}`,
	} {
		assertUnknown(t, mapUsage("codex", []byte(body)))
	}
	// The window duration, not primary/secondary position, identifies the weekly quota.
	response := mapUsage("codex", []byte(`{"rate_limit":{"primary_window":{"used_percent":0,"reset_at":1791334800,"limit_window_seconds":604800}}}`))
	if response.Status != "known" || response.Groups[0].Buckets[0].Window != "7d" || response.Groups[0].Buckets[0].RemainingFraction != 1 || response.Groups[0].Buckets[0].ResetTime != time.Unix(1791334800, 0).UTC().Format(time.RFC3339) {
		t.Fatal("weekly-only quota mapped incorrectly")
	}
}
