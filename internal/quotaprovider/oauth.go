// Package quotaprovider reads the same OAuth usage endpoints as the management dashboard.
package quotaprovider

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"golang.org/x/sync/singleflight"
)

const cacheTTL = 5 * time.Minute
const maxBodyBytes = 64 << 10
const upstreamRequestTimeout = 15 * time.Second

// Credential resolves tokens and transport inside the cache's single-flight operation.
// The transport must not capture request headers or bodies in request logs.
type Credential struct {
	Token     string
	AccountID string
	Transport http.RoundTripper
}
type Resolver func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error)

type cachedQuota struct {
	response pluginapi.QuotaFetchResponse
	expires  time.Time
}

// OAuth is an in-process quota provider for Codex and Claude credentials.
type OAuth struct {
	resolve        Resolver
	requestTimeout time.Duration
	now            func() time.Time
	mu             sync.Mutex
	cache          map[string]cachedQuota
	flights        singleflight.Group
}

var _ pluginapi.QuotaProvider = (*OAuth)(nil)

func New(resolve Resolver) *OAuth {
	return &OAuth{resolve: resolve, requestTimeout: upstreamRequestTimeout, now: time.Now, cache: make(map[string]cachedQuota)}
}
func (*OAuth) Identifier() string { return "oauth-usage" }
func (*OAuth) DescribeQuota(context.Context, pluginapi.QuotaDescribeRequest) (pluginapi.QuotaDescribeResponse, error) {
	return pluginapi.QuotaDescribeResponse{SupportedProviders: []string{"codex", "claude"}, DisplayName: "Built-in OAuth usage"}, nil
}
func (*OAuth) ResetQuota(context.Context, pluginapi.QuotaResetRequest) (pluginapi.QuotaResetResponse, error) {
	return pluginapi.QuotaResetResponse{Message: "OAuth usage cannot be reset"}, nil
}
func unknown() pluginapi.QuotaFetchResponse { return pluginapi.QuotaFetchResponse{Status: "unknown"} }

// FetchQuota caches successes AND failures; an upstream failure never becomes a numeric quota.
func (p *OAuth) FetchQuota(ctx context.Context, req pluginapi.QuotaFetchRequest) (pluginapi.QuotaFetchResponse, error) {
	if err := ctx.Err(); err != nil {
		return unknown(), err
	}
	id := req.AuthID
	if id == "" {
		id = req.AuthIndex
	}
	if id == "" || (req.Provider != "codex" && req.Provider != "claude") {
		return unknown(), nil
	}
	key := req.Provider + ":" + id
	result := p.flights.DoChan(key, func() (any, error) {
		p.mu.Lock()
		cached, ok := p.cache[key]
		now := p.now()
		if ok && now.Before(cached.expires) {
			p.mu.Unlock()
			return cached.response, nil
		}
		// Expired entries contain no credential material and can be discarded.
		for k, entry := range p.cache {
			if !now.Before(entry.expires) {
				delete(p.cache, k)
			}
		}
		p.mu.Unlock()
		// Preserve context values, but no caller owns the shared operation's lifetime.
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.requestTimeout)
		defer cancel()
		response := p.fetch(fetchCtx, req)
		p.mu.Lock()
		p.cache[key] = cachedQuota{response: response, expires: p.now().Add(cacheTTL)}
		p.mu.Unlock()
		return response, nil
	})
	select {
	case <-ctx.Done():
		return unknown(), ctx.Err()
	case value := <-result:
		if err := ctx.Err(); err != nil {
			return unknown(), err
		}
		response := value.Val.(pluginapi.QuotaFetchResponse)
		// Do not let a consumer mutate the shared cache.
		response.Groups = append([]pluginapi.QuotaGroup(nil), response.Groups...)
		for i := range response.Groups {
			response.Groups[i].Buckets = append([]pluginapi.QuotaBucket(nil), response.Groups[i].Buckets...)
		}
		return response, nil
	}
}

func (p *OAuth) fetch(ctx context.Context, req pluginapi.QuotaFetchRequest) pluginapi.QuotaFetchResponse {
	if p.resolve == nil {
		return unknown()
	}
	credential, err := p.resolve(ctx, req)
	if err != nil || credential.Token == "" {
		return unknown()
	}
	endpoint := "https://chatgpt.com/backend-api/wham/usage"
	if req.Provider == "claude" {
		endpoint = "https://api.anthropic.com/api/oauth/usage"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return unknown()
	}
	request.Header.Set("Authorization", "Bearer "+credential.Token)
	request.Header.Set("Accept", "application/json")
	if req.Provider == "claude" {
		request.Header.Set("anthropic-beta", "oauth-2025-04-20")
	}
	if req.Provider == "codex" && credential.AccountID != "" {
		request.Header.Set("Chatgpt-Account-Id", credential.AccountID)
	}
	// Deliberately bypass HostHTTPClient's request capture: OAuth tokens must never reach logs.
	client := &http.Client{Timeout: p.requestTimeout, Transport: credential.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return unknown()
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return unknown()
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		return unknown()
	}
	return mapUsage(req.Provider, body)
}

type claudeWindow struct {
	Used  *float64 `json:"utilization"`
	Reset string   `json:"resets_at"`
}
type codexWindow struct {
	Used    *float64 `json:"used_percent"`
	Reset   *int64   `json:"reset_at"`
	Seconds *int64   `json:"limit_window_seconds"`
}

func bucket(window string, used *float64, reset string) (pluginapi.QuotaBucket, bool) {
	if used == nil || math.IsNaN(*used) || math.IsInf(*used, 0) || *used < 0 || *used > 100 {
		return pluginapi.QuotaBucket{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, reset)
	if err != nil {
		return pluginapi.QuotaBucket{}, false
	}
	return pluginapi.QuotaBucket{Window: window, RemainingFraction: (100 - *used) / 100, ResetTime: parsed.UTC().Format(time.RFC3339Nano)}, true
}
func mapUsage(provider string, body []byte) pluginapi.QuotaFetchResponse {
	var buckets []pluginapi.QuotaBucket
	if provider == "claude" {
		var payload struct {
			FiveHour *claudeWindow `json:"five_hour"`
			SevenDay *claudeWindow `json:"seven_day"`
		}
		if json.Unmarshal(body, &payload) != nil {
			return unknown()
		}
		for _, item := range []struct {
			name   string
			window *claudeWindow
		}{{"5h", payload.FiveHour}, {"7d", payload.SevenDay}} {
			if item.window == nil {
				continue
			}
			b, ok := bucket(item.name, item.window.Used, item.window.Reset)
			if !ok {
				return unknown()
			}
			buckets = append(buckets, b)
		}
	} else {
		var payload struct {
			RateLimit *struct {
				Primary   *codexWindow `json:"primary_window"`
				Secondary *codexWindow `json:"secondary_window"`
			} `json:"rate_limit"`
		}
		if json.Unmarshal(body, &payload) != nil || payload.RateLimit == nil {
			return unknown()
		}
		for _, w := range []*codexWindow{payload.RateLimit.Primary, payload.RateLimit.Secondary} {
			if w == nil {
				continue
			}
			if w.Reset == nil || *w.Reset <= 0 || w.Seconds == nil {
				return unknown()
			}
			name := ""
			switch *w.Seconds {
			case 18000:
				name = "5h"
			case 604800:
				name = "7d"
			default:
				return unknown()
			}
			b, ok := bucket(name, w.Used, time.Unix(*w.Reset, 0).UTC().Format(time.RFC3339))
			if !ok {
				return unknown()
			}
			buckets = append(buckets, b)
		}
	}
	if len(buckets) == 0 {
		return unknown()
	}
	return pluginapi.QuotaFetchResponse{Status: "known", Groups: []pluginapi.QuotaGroup{{DisplayName: "Usage", Buckets: buckets}}}
}
