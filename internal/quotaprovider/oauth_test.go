package quotaprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

const testToken = "fake-quota-token-never-log"

var fixture = map[string]string{
	"claude": `{"five_hour":{"utilization":1,"resets_at":"2026-10-07T01:00:00Z"},"seven_day":{"utilization":73,"resets_at":"2026-10-12T01:00:00Z"}}`,
	"codex":  `{"rate_limit":{"primary_window":{"used_percent":1,"reset_at":1791334800,"limit_window_seconds":18000},"secondary_window":{"used_percent":73,"reset_at":1791766800,"limit_window_seconds":604800}}}`,
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func redirectedTransport(server *httptest.Server) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		clone.URL.Scheme = "http"
		clone.URL.Host = strings.TrimPrefix(server.URL, "http://")
		return server.Client().Transport.RoundTrip(clone)
	})
}
func request(provider, id string) pluginapi.QuotaFetchRequest {
	return pluginapi.QuotaFetchRequest{Provider: provider, AuthID: id, AuthIndex: id}
}
func fetch(t *testing.T, p *OAuth, req pluginapi.QuotaFetchRequest) pluginapi.QuotaFetchResponse {
	t.Helper()
	response, err := p.FetchQuota(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
func assertUnknown(t *testing.T, response pluginapi.QuotaFetchResponse) {
	t.Helper()
	if response.Status != "unknown" || len(response.Groups) != 0 || len(response.Summary) != 0 || response.Subscription != nil {
		t.Fatalf("not unknown: %+v", response)
	}
}

func TestOAuthSuccess(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path := "/backend-api/wham/usage"
				if provider == "claude" {
					path = "/api/oauth/usage"
					if r.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
						t.Error("missing OAuth beta")
					}
				}
				if r.URL.Path != path || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Accept") != "application/json" {
					t.Error("incorrect quota request")
				}
				if provider == "codex" && r.Header.Get("Chatgpt-Account-Id") != "fake-account" {
					t.Error("missing Codex account")
				}
				_, _ = io.WriteString(w, fixture[provider])
			}))
			defer server.Close()
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, AccountID: "fake-account", Transport: redirectedTransport(server)}, nil
			})
			response := fetch(t, p, request(provider, "one"))
			if response.Status != "known" || len(response.Groups) != 1 || len(response.Groups[0].Buckets) != 2 {
				t.Fatalf("wrong shape: %+v", response)
			}
			buckets := response.Groups[0].Buckets
			if buckets[0].Window != "5h" || buckets[0].RemainingFraction != .99 || buckets[1].Window != "7d" || buckets[1].RemainingFraction != .27 {
				t.Fatalf("wrong percentages: %+v", buckets)
			}
			for _, b := range buckets {
				if _, err := time.Parse(time.RFC3339, b.ResetTime); err != nil {
					t.Fatal(err)
				}
			}
			response.Groups[0].Buckets[0].RemainingFraction = 0
			if fetch(t, p, request(provider, "one")).Groups[0].Buckets[0].RemainingFraction != .99 {
				t.Fatal("cache mutated by consumer")
			}
		})
	}
}

func TestOAuthFailuresUnknownAndNoSecrets(t *testing.T) {
	var logs bytes.Buffer
	logger := log.StandardLogger()
	old := logger.Out
	logger.SetOutput(&logs)
	defer logger.SetOutput(old)
	for _, provider := range []string{"codex", "claude"} {
		for _, status := range []int{401, 429, 500, 502, 503} {
			t.Run(provider+"/"+http.StatusText(status), func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(status)
					_, _ = io.WriteString(w, testToken)
				}))
				defer server.Close()
				p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
					return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
				})
				for i := 0; i < 2; i++ {
					response := fetch(t, p, request(provider, "one"))
					assertUnknown(t, response)
					encoded, _ := json.Marshal(response)
					if strings.Contains(string(encoded), testToken) {
						t.Fatal("secret in output")
					}
				}
				if calls.Load() != 1 {
					t.Fatal("failures not cached")
				}
			})
		}
		for _, body := range []string{testToken, `{}`, `null`, `{"five_hour":{"utilization":null,"resets_at":"2026-10-07T01:00:00Z"}}`, `{"seven_day":{"utilization":101,"resets_at":"2026-10-07T01:00:00Z"}}`, `{"seven_day":{"utilization":0,"resets_at":"` + testToken + `"}}`, strings.Repeat("x", maxBodyBytes+1)} {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
			})
			assertUnknown(t, fetch(t, p, request(provider, "one")))
			server.Close()
		}
		for _, failure := range []Resolver{
			func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{}, errors.New(testToken)
			},
			func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) { return Credential{}, nil },
			func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New(testToken) })}, nil
			},
		} {
			assertUnknown(t, fetch(t, New(failure), request(provider, "one")))
		}
	}
	if strings.Contains(logs.String(), testToken) {
		t.Fatal("secret in logs")
	}
}

func TestOAuthSingleFlightCacheExpiryAndCredentialIsolation(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			var calls, resolutions atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					close(entered)
					<-release
				}
				_, _ = io.WriteString(w, fixture[provider])
			}))
			defer server.Close()
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				resolutions.Add(1)
				return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
			})
			now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
			p.now = func() time.Time { return now }
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < 32; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					response, err := p.FetchQuota(context.Background(), request(provider, "one"))
					if err != nil || response.Status != "known" {
						t.Error("concurrent fetch failed")
					}
				}()
			}
			close(start)
			<-entered
			close(release)
			wg.Wait()
			if calls.Load() != 1 || resolutions.Load() != 1 {
				t.Fatalf("not single-flight: calls=%d resolves=%d", calls.Load(), resolutions.Load())
			}
			now = now.Add(cacheTTL - time.Nanosecond)
			fetch(t, p, request(provider, "one"))
			if calls.Load() != 1 {
				t.Fatal("expired early")
			}
			now = now.Add(time.Nanosecond)
			fetch(t, p, request(provider, "one"))
			if calls.Load() != 2 {
				t.Fatal("not refreshed at expiry")
			}
			fetch(t, p, request(provider, "two"))
			if calls.Load() != 3 {
				t.Fatal("credentials share cache")
			}
		})
	}
}

func TestOAuthRedirectDoesNotForwardCredential(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
		return Credential{Token: testToken, Transport: redirectedTransport(source)}, nil
	})
	for _, provider := range []string{"codex", "claude"} {
		assertUnknown(t, fetch(t, p, request(provider, "one")))
	}
	if calls.Load() != 0 {
		t.Fatal("followed OAuth redirect")
	}
}
