package auth

import (
	"context"
	"errors"
	"math"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type clientRequestedModelContextKey struct{}

type apiKeyDailyUsage struct {
	mu      sync.Mutex
	day     string
	tokens  map[string]int64
	records map[string]map[string]int64
	now     func() time.Time
}

func (u *apiKeyDailyUsage) todayLocked() string {
	now := time.Now()
	if u.now != nil {
		now = u.now()
	}
	day := now.UTC().Format("2006-01-02")
	if u.day != day {
		u.day = day
		u.tokens = make(map[string]int64)
		u.records = make(map[string]map[string]int64)
	}
	return day
}

// WithClientRequest binds the client-visible model and the existing usage record
// publisher to this manager's per-key accounting. Call before selection/dispatch.
func (m *Manager) WithClientRequest(ctx context.Context, model string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(model) != "" {
		ctx = context.WithValue(ctx, clientRequestedModelContextKey{}, strings.TrimSpace(model))
	}
	if m == nil {
		return ctx
	}
	return coreusage.WithRecordObserver(ctx, func(record coreusage.Record) { m.recordClientUsage(ctx, record) })
}

// ClientRequestedModelFromContext returns the immutable client-visible model,
// including the model retained when a realtime client secret is minted.
func ClientRequestedModelFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	model, _ := ctx.Value(clientRequestedModelContextKey{}).(string)
	return model
}

func (m *Manager) HasClientModelPolicy(ctx context.Context) bool {
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if policy.AllowedModels != nil {
			return true
		}
	}
	return false
}

func clientModelForRequest(ctx context.Context, opts coreexecutor.Options, fallback string) string {
	if model := requestedModelFromMetadata(opts.Metadata, ""); model != "" {
		return model
	}
	if ctx != nil {
		if model, ok := ctx.Value(clientRequestedModelContextKey{}).(string); ok && model != "" {
			return model
		}
	}
	return fallback
}

// ValidateMeteredClientRoute rejects capped keys on transports that do not
// publish token usage; silently accepting them would bypass daily accounting.
func (m *Manager) ValidateMeteredClientRoute(ctx context.Context) error {
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if policy.DailyTokenCap != nil {
			return &Error{Code: "api_key_usage_unavailable", Message: "daily-token-cap requires recorded usage; direct Realtime/media transport is unavailable for capped client keys", HTTPStatus: http.StatusServiceUnavailable}
		}
	}
	return nil
}

func (m *Manager) recordClientUsage(ctx context.Context, record coreusage.Record) {
	digest, _ := ctx.Value(clientAPIKeyHashContextKey{}).(string)
	if digest == "" {
		return
	}
	tokens := nonnegativePolicyTokens(record.Detail.InputTokens)
	output := nonnegativePolicyTokens(record.Detail.OutputTokens)
	if output > math.MaxInt64-tokens {
		tokens = math.MaxInt64
	} else {
		tokens += output
	}
	u := &m.apiKeyUsage
	u.mu.Lock()
	defer u.mu.Unlock()
	u.todayLocked()
	if record.RequestID != "" {
		if u.records[digest] == nil {
			u.records[digest] = make(map[string]int64)
		}
		previous := u.records[digest][record.RequestID]
		if tokens <= previous {
			return
		}
		u.records[digest][record.RequestID] = tokens
		tokens -= previous
	}
	current := u.tokens[digest]
	if tokens > math.MaxInt64-current {
		u.tokens[digest] = math.MaxInt64
	} else {
		u.tokens[digest] = current + tokens
	}
}

func nonnegativePolicyTokens(tokens int64) int64 {
	if tokens < 0 {
		return 0
	}
	return tokens
}

// ValidateClientRequest refuses disallowed client-visible model names before
// credential selection. It also checks the recorded UTC-day input+output total.
func (m *Manager) ValidateClientRequest(ctx context.Context, model string) error {
	ctx = m.withAPIKeyPolicies(ctx)
	policies := apiKeyPoliciesFromContext(ctx)
	model = strings.TrimSpace(model)
	for _, policy := range policies {
		if policy.AllowedModels != nil {
			allowed := false
			for _, pattern := range *policy.AllowedModels {
				if matched, err := path.Match(pattern, model); err == nil && matched {
					allowed = true
					break
				}
			}
			if !allowed {
				return &Error{Code: "api_key_model_forbidden", Message: "requested model is outside the client API key allowed-models", HTTPStatus: http.StatusForbidden}
			}
		}
	}
	return m.validateClientTokenCap(ctx)
}

func (m *Manager) validateClientTokenCap(ctx context.Context) error {
	if m == nil {
		return nil
	}
	policies := apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx))
	if len(policies) == 0 {
		return nil
	}
	digest, _ := ctx.Value(clientAPIKeyHashContextKey{}).(string)
	if digest == "" {
		return nil
	}
	u := &m.apiKeyUsage
	u.mu.Lock()
	defer u.mu.Unlock()
	u.todayLocked()
	for _, policy := range policies {
		if policy.DailyTokenCap != nil && u.tokens[digest] >= *policy.DailyTokenCap {
			return &Error{Code: "api_key_daily_token_cap", Message: "client API key daily token cap reached; retry after 00:00 UTC", HTTPStatus: http.StatusTooManyRequests}
		}
	}
	return nil
}

func isAPIKeyControlError(err error) bool {
	var policyErr *Error
	return errors.As(err, &policyErr) && (policyErr.Code == "api_key_model_forbidden" || policyErr.Code == "api_key_daily_token_cap")
}
