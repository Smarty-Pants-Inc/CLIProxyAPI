package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/quotaprovider"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type quotaTestTransport func(*http.Request) (*http.Response, error)

func (f quotaTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestBuiltinQuotaManagementFetchRealPath(t *testing.T) {
	const token = "fake-dashboard-token-never-log"
	var logs bytes.Buffer
	logger := log.StandardLogger()
	oldOut, oldLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&logs)
	logger.SetLevel(log.TraceLevel)
	defer func() { logger.SetOutput(oldOut); logger.SetLevel(oldLevel) }()
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("not dashboard token")
				}
				if provider == "claude" {
					_, _ = io.WriteString(w, `{"five_hour":{"utilization":25,"resets_at":"2026-10-07T00:00:00Z"},"seven_day":{"utilization":80,"resets_at":"2026-10-12T00:00:00Z"}}`)
				} else {
					_, _ = io.WriteString(w, `{"rate_limit":{"primary_window":{"used_percent":25,"reset_at":1791334800,"limit_window_seconds":18000},"secondary_window":{"used_percent":80,"reset_at":1791766800,"limit_window_seconds":604800}}}`)
				}
			}))
			defer server.Close()
			manager := coreauth.NewManager(nil, nil, nil)
			auth := &coreauth.Auth{ID: provider + "-dashboard", Provider: provider, Metadata: map[string]any{"access_token": token}}
			auth.EnsureIndex()
			if _, err := manager.Register(context.Background(), auth); err != nil {
				t.Fatal(err)
			}
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
			host := pluginhost.New()
			// Only replace the upstream transport with httptest; production handlers,
			// host dispatch, dashboard credential resolution, cache and mapper all run.
			builtin := quotaprovider.New(func(ctx context.Context, req pluginapi.QuotaFetchRequest) (quotaprovider.Credential, error) {
				credential, err := h.resolveQuotaCredential(ctx, req)
				credential.Transport = quotaTestTransport(func(r *http.Request) (*http.Response, error) {
					clone := r.Clone(r.Context())
					clone.URL.Scheme = "http"
					clone.URL.Host = strings.TrimPrefix(server.URL, "http://")
					return server.Client().Transport.RoundTrip(clone)
				})
				return credential, err
			})
			builtin.Admit = h.newBuiltinQuotaProvider().Admit
			host.RegisterBuiltinQuotaProvider(builtin)
			h.SetPluginHost(host)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/quota/fetch", strings.NewReader(`{"auth_index":"`+auth.Index+`"}`))
			ctx.Request.Header.Set("Content-Type", "application/json")
			h.FetchCredentialQuota(ctx)
			var response pluginapi.QuotaFetchResponse
			if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || response.Status != "known" || len(response.Groups) != 1 || len(response.Groups[0].Buckets) != 2 {
				t.Fatalf("fetch failed: %d %s", rec.Code, rec.Body.String())
			}
			if response.Groups[0].Buckets[0].RemainingFraction != .75 || response.Groups[0].Buckets[1].RemainingFraction != .2 {
				t.Fatalf("dashboard mismatch: %s", rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), token) {
				t.Fatal("token in API output")
			}
			t.Logf("POST /v0/management/quota/fetch (%s): %d %s", provider, rec.Code, rec.Body.String())
		})
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("token in management logs")
	}
}

func TestBuiltinQuotaRegisteredWithoutPluginsAndSurvivesReload(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	host := pluginhost.New()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.SetPluginHost(host)
	for _, provider := range []string{"codex", "claude"} {
		auth := &coreauth.Auth{ID: provider + "-one", Provider: provider, Metadata: map[string]any{"access_token": "fake-in-process-token", "account_id": "fake-account"}}
		auth.EnsureIndex()
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		credential, err := h.resolveQuotaCredential(context.Background(), pluginapi.QuotaFetchRequest{Provider: provider, AuthID: auth.ID, AuthIndex: auth.Index})
		if err != nil || credential.Token != "fake-in-process-token" || credential.AccountID != "fake-account" || credential.Transport == nil {
			t.Fatal("dashboard credential resolution failed")
		}
		if _, err := h.resolveQuotaCredential(context.Background(), pluginapi.QuotaFetchRequest{Provider: "wrong", AuthID: auth.ID, AuthIndex: auth.Index}); err == nil {
			t.Fatal("accepted provider mismatch")
		}
	}
	for i := 0; i < 2; i++ {
		host.ApplyConfig(context.Background(), &config.Config{})
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/quota/providers", nil)
		h.GetQuotaProviders(ctx)
		var response struct {
			Providers []pluginhost.RegisteredQuotaProviderInfo `json:"providers"`
		}
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || len(response.Providers) != 1 {
			t.Fatalf("provider registration failed: %s", rec.Body.String())
		}
		supported := response.Providers[0].SupportedProviders
		if len(supported) != 2 || supported[0] != "codex" || supported[1] != "claude" || response.Providers[0].SupportsReset {
			t.Fatalf("wrong capabilities: %+v", response)
		}
		for _, provider := range []string{"codex", "claude"} {
			if !host.HasQuotaProvider(provider) {
				t.Fatalf("missing %s", provider)
			}
			if _, ok := host.QuotaSupportedProvidersSet(context.Background())[provider]; !ok {
				t.Fatalf("missing supported provider %s", provider)
			}
		}
		if len(host.RegisteredPlugins()) != 0 {
			t.Fatal("built-in exposed as removable dynamic plugin")
		}
		h.SetPluginHost(host)
	}
}

func TestBuiltinQuotaUnknownOnManagementFetch(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
	h.SetPluginHost(pluginhost.New())
	for _, provider := range []string{"codex", "claude"} {
		// An OAuth credential whose access token is missing is owned by the builtin and reads unknown.
		auth := &coreauth.Auth{ID: provider + "-no-token", Provider: provider, Metadata: map[string]any{"refresh_token": "fake-refresh"}}
		auth.EnsureIndex()
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/quota/fetch", strings.NewReader(`{"auth_index":"`+auth.Index+`"}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		h.FetchCredentialQuota(ctx)
		if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"status":"unknown"}` {
			t.Fatalf("unsafe unknown response: %d %s", rec.Code, rec.Body.String())
		}
	}
}

// recordOutboundDials makes the dashboard transport refuse and count every dial
// except to allowAddr, so a test sees any OAuth request the production path makes.
func recordOutboundDials(t *testing.T, allowAddr string) *atomic.Int32 {
	t.Helper()
	var blocked atomic.Int32
	old := http.DefaultTransport
	var dialer net.Dialer
	http.DefaultTransport = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == allowAddr {
			return dialer.DialContext(ctx, network, addr)
		}
		blocked.Add(1)
		return nil, errors.New("outbound dial blocked by test")
	}}
	t.Cleanup(func() { http.DefaultTransport = old })
	return &blocked
}

func postQuotaFetch(h *Handler, authIndex string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/quota/fetch", strings.NewReader(`{"auth_index":"`+authIndex+`"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	h.FetchCredentialQuota(ctx)
	return rec
}

func TestBuiltinQuotaNeverSendsAPIKeysToOAuthEndpoints(t *testing.T) {
	const secret = "third-party-api-key-never-send"
	dials := recordOutboundDials(t, "")
	for _, provider := range []string{"codex", "claude"} {
		for name, auth := range map[string]*coreauth.Auth{
			"config-api-key":   {Attributes: map[string]string{"api_key": secret, "base_url": "https://third-party.example/v1", "auth_kind": "apikey"}},
			"attr-api-key":     {Attributes: map[string]string{"api_key": secret, "base_url": "https://third-party.example/v1"}},
			"metadata-api-key": {Metadata: map[string]any{"api_key": secret}},
			"session-token":    {Attributes: map[string]string{"session_token": secret}},
		} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				manager := coreauth.NewManager(nil, nil, nil)
				auth.ID, auth.Provider = provider+"-"+name, provider
				auth.EnsureIndex()
				if _, err := manager.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
				h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
				h.SetPluginHost(pluginhost.New())
				before := dials.Load()
				rec := postQuotaFetch(h, auth.Index)
				if dials.Load() != before {
					t.Fatal("API-key credential sent to an OAuth usage endpoint")
				}
				if rec.Code != http.StatusNotImplemented || strings.Contains(rec.Body.String(), secret) {
					t.Fatalf("builtin consumed an API-key credential: %d %s", rec.Code, rec.Body.String())
				}
			})
		}
	}
}

func TestBuiltinQuotaOAuthControlStillFetches(t *testing.T) {
	dials := recordOutboundDials(t, "")
	for _, provider := range []string{"codex", "claude"} {
		manager := coreauth.NewManager(nil, nil, nil)
		auth := &coreauth.Auth{ID: provider + "-oauth", Provider: provider, Metadata: map[string]any{"access_token": "fake-oauth", "refresh_token": "fake-refresh"}}
		auth.EnsureIndex()
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatal(err)
		}
		h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
		h.SetPluginHost(pluginhost.New())
		before := dials.Load()
		rec := postQuotaFetch(h, auth.Index)
		// The blocked dial is the OAuth request; its failure is reported as unknown.
		if dials.Load() == before || rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"status":"unknown"}` {
			t.Fatalf("%s OAuth control did not reach builtin: dials=%d %d %s", provider, dials.Load()-before, rec.Code, rec.Body.String())
		}
	}
}

func TestBuiltinQuotaPreservesDeclarativeProbe(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"summary":[{"key":"balance","label":"Balance","value":42,"unit":"credits"}]}`)
	}))
	defer upstream.Close()
	dials := recordOutboundDials(t, strings.TrimPrefix(upstream.URL, "http://"))
	for _, provider := range []string{"codex", "claude"} {
		for name, metadata := range map[string]map[string]any{
			"oauth-with-token": {"access_token": "fake-oauth", "refresh_token": "fake-refresh"},
			"tokenless":        {},
		} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				metadata["quota_probe"] = map[string]any{"url": upstream.URL, "method": "GET"}
				manager := coreauth.NewManager(nil, nil, nil)
				auth := &coreauth.Auth{ID: provider + "-" + name, Provider: provider, Metadata: metadata}
				auth.EnsureIndex()
				if _, err := manager.Register(context.Background(), auth); err != nil {
					t.Fatal(err)
				}
				h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
				h.SetPluginHost(pluginhost.New())
				before := dials.Load()
				rec := postQuotaFetch(h, auth.Index)
				if dials.Load() != before || rec.Code != 200 || !strings.Contains(rec.Body.String(), `"balance"`) {
					t.Fatalf("declarative probe not used: dials=%d %d %s", dials.Load()-before, rec.Code, rec.Body.String())
				}
			})
		}
	}
}
