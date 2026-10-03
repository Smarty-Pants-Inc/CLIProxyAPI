package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	tr "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Exercise the real manager admission, header expansion and HTTP/SSE transports.
// The gateway observes Host independently of the fixed TCP endpoint, as in F27.
func TestCodexRestrictedAuthorityHTTPAndSSE(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, tc := range []struct {
			name, host          string
			restricted, refused bool
		}{
			{"client_host_restricted", "$X-Route", true, true},
			{"session_host_restricted", "tenant-$CPA-SESSION-ID", true, true},
			{"static_host_restricted", "fixed-tenant.example", true, false},
			{"endpoint_host_restricted", "", true, false},
			{"client_host_unpolicied", "$X-Route", false, false},
		} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				type send struct{ host, path, bearer, probe string }
				var mu sync.Mutex
				var sends []send
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					mu.Lock()
					sends = append(sends, send{r.Host, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("X-Probe")})
					mu.Unlock()
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6.1-sol\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")
				}))
				defer upstream.Close()
				u, err := url.Parse(upstream.URL)
				if err != nil {
					t.Fatal(err)
				}
				cfg := &config.Config{CodexKey: []config.CodexKey{{APIKey: "synthetic-bearer", BaseURL: upstream.URL, Headers: map[string]string{"hOsT": tc.host, "X-Probe": "$X-Route"}}}}
				credentials, err := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{Config: cfg, IDGenerator: synthesizer.NewStableIDGenerator()})
				if err != nil || len(credentials) != 1 {
					t.Fatalf("config synthesis: credentials=%d error=%v", len(credentials), err)
				}
				a := credentials[0]
				id := a.ID
				registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
				m := auth.NewManager(nil, nil, nil)
				m.SetConfig(cfg)
				m.RegisterExecutor(NewCodexExecutor(cfg))
				if _, err := m.Register(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256([]byte("synthetic-client"))
				policy := config.APIKeyPolicy{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{id}}
				for _, route := range []string{u.Host, "other-tenant.example"} {
					c, _ := gin.CreateTestContext(httptest.NewRecorder())
					c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
					c.Request.Header.Set("X-Route", route)
					ctx := util.WithSessionID(context.WithValue(context.Background(), "gin", c), route)
					done := func() {}
					if tc.restricted {
						ctx, done, err = m.BeginKeyPolicy(ctx, []config.APIKeyPolicy{policy}, "gpt-6.1-sol")
						if err != nil {
							t.Fatal(err)
						}
					}
					req := ex.Request{Model: "gpt-6.1-sol", Payload: []byte(`{"model":"gpt-6.1-sol","input":"synthetic"}`)}
					opts := ex.Options{SourceFormat: tr.FromString("openai-response"), Headers: c.Request.Header}
					if stream {
						var result *ex.StreamResult
						result, err = m.ExecuteStream(ctx, []string{"codex"}, req, opts)
						if err == nil {
							for chunk := range result.Chunks {
								if chunk.Err != nil {
									err = chunk.Err
								}
							}
						}
					} else {
						_, err = m.Execute(ctx, []string{"codex"}, req, opts)
					}
					done()
					if tc.refused {
						if err == nil {
							t.Errorf("client-derived authority accepted for X-Route=%q", route)
						}
						if err != nil && !strings.Contains(err.Error(), "api_key_policy_unavailable") {
							t.Errorf("unsafe/unexpected error: %v", err)
						}
					} else if err != nil {
						t.Fatalf("allowed send failed: %v", err)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if tc.refused {
					if len(sends) != 0 {
						t.Fatalf("F27: restricted credential reached transport: %+v", sends)
					}
					return
				}
				if len(sends) != 2 {
					t.Fatalf("sends=%d, want 2", len(sends))
				}
				for i, got := range sends {
					wantHost := u.Host
					if tc.host == "fixed-tenant.example" {
						wantHost = tc.host
					}
					if !tc.restricted && i == 1 {
						wantHost = "other-tenant.example"
					}
					wantProbe := u.Host
					if i == 1 {
						wantProbe = "other-tenant.example"
					}
					if got.host != wantHost || got.path != "/responses" || got.bearer != "Bearer synthetic-bearer" || got.probe != wantProbe {
						t.Errorf("send=%+v, want host=%q fixed path/bearer, probe=%q", got, wantHost, wantProbe)
					}
				}
			})
		}
	}
}

// A restricted client must not bypass the final URL/Host fence even if a request
// builder supplies a different URL, path or pre-populated authority.
func TestCodexRestrictedFinalEndpoint(t *testing.T) {
	for _, change := range []string{"url", "path", "opaque_url", "host", "header_host", "fixed", "static", "unpolicied"} {
		t.Run(change, func(t *testing.T) {
			var calls atomic.Int64
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			upstream := httptest.NewServer(handler)
			defer upstream.Close()
			other := httptest.NewServer(handler)
			defer other.Close()
			m := auth.NewManager(nil, nil, nil)
			m.SetConfig(&config.Config{})
			ctx := context.Background()
			if change != "unpolicied" {
				var done func()
				var err error
				ctx, done, err = m.BeginKeyPolicy(ctx, []config.APIKeyPolicy{{KeySHA256: strings.Repeat("a", 64)}}, "gpt-6.1-sol")
				if err != nil {
					t.Fatal(err)
				}
				defer done()
			}
			a := &auth.Auth{Provider: "codex", Attributes: map[string]string{"base_url": upstream.URL}}
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL+"/responses", strings.NewReader(`{"model":"gpt-6.1-sol"}`))
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "url":
				a.Attributes["base_url"] = "http://fixed.example"
			case "path":
				r.URL.Path = "/other"
			case "opaque_url":
				// URL.String can hide a changed TCP authority behind Opaque.
				r.URL.Opaque = "//" + r.URL.Host + r.URL.Path
				r.URL.Host = strings.TrimPrefix(other.URL, "http://")
				r.URL.Path = ""
			case "host", "unpolicied":
				r.Host = "other-tenant.example"
			case "header_host":
				r.Header.Set("Host", "other-tenant.example")
			case "static":
				a.Attributes["header:Host"] = "fixed-tenant.example"
				r.Host = "fixed-tenant.example"
				r.Header.Set("Host", "fixed-tenant.example")
			}
			client := helps.NewUtlsHTTPClient(ctx, &config.Config{}, a, 0)
			resp, err := client.Do(r)
			if resp != nil {
				if errClose := resp.Body.Close(); errClose != nil {
					t.Fatal(errClose)
				}
			}
			refused := change != "fixed" && change != "static" && change != "unpolicied"
			if refused {
				if err == nil || calls.Load() != 0 {
					t.Fatalf("final endpoint drift accepted: error=%v calls=%d", err, calls.Load())
				}
			} else if err != nil || calls.Load() != 1 {
				t.Fatalf("fixed/static/unpolicied send failed: error=%v calls=%d", err, calls.Load())
			}
		})
	}
}

type codexAuthorityTestTransport func(*http.Request) (*http.Response, error)

func (f codexAuthorityTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Preserve the ordinary OAuth path with no api_key/base_url attributes. Intercept
// only the last transport so this proof never dials the public credential endpoint.
func TestCodexRestrictedDefaultOAuthEndpoint(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			id := "F27-default-oauth-" + t.Name()
			registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
			defer registry.GetGlobalRegistry().UnregisterClient(id)
			cfg := &config.Config{}
			m := auth.NewManager(nil, nil, nil)
			m.SetConfig(cfg)
			m.RegisterExecutor(NewCodexExecutor(cfg))
			if _, err := m.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic-oauth-token", "account_id": "synthetic-account"}}); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int64
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", codexAuthorityTestTransport(func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if r.URL.String() != "https://chatgpt.com/backend-api/codex/responses" || r.URL.Scheme != "https" || r.URL.Host != "chatgpt.com" || r.Host != "chatgpt.com" || r.Header.Get("Authorization") != "Bearer synthetic-oauth-token" || r.Header.Get("Chatgpt-Account-Id") != "synthetic-account" {
					t.Errorf("default OAuth binding changed: URL=%s Host=%q bearer=%q account=%q", r.URL, r.Host, r.Header.Get("Authorization"), r.Header.Get("Chatgpt-Account-Id"))
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6.1-sol\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n")), Request: r}, nil
			}))
			ctx, done, err := m.BeginKeyPolicy(ctx, []config.APIKeyPolicy{{KeySHA256: strings.Repeat("b", 64), AllowedAuths: []string{id}}}, "gpt-6.1-sol")
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			req := ex.Request{Model: "gpt-6.1-sol", Payload: []byte(`{"model":"gpt-6.1-sol","input":"synthetic"}`)}
			opts := ex.Options{SourceFormat: tr.FromString("openai-response")}
			if stream {
				var result *ex.StreamResult
				result, err = m.ExecuteStream(ctx, []string{"codex"}, req, opts)
				if err == nil {
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							err = chunk.Err
						}
					}
				}
			} else {
				_, err = m.Execute(ctx, []string{"codex"}, req, opts)
			}
			if err != nil || calls.Load() != 1 {
				t.Fatalf("default OAuth send failed: error=%v calls=%d", err, calls.Load())
			}
		})
	}
}
