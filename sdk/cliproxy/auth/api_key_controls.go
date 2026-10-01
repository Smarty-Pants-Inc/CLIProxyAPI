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
type clientRequestAdmissionContextKey struct{}

type clientRequestAdmission struct {
	manager *Manager
	digest  string
	ordinal int64
}

type apiKeyDailyUsage struct {
	mu       sync.Mutex
	day      string
	tokens   map[string]int64
	requests map[string]int64
	records  map[string]map[string]int64
	now      func() time.Time
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
		u.requests = make(map[string]int64)
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
	// Home's requestedModelFromMetadata uses "unknown" for missing metadata;
	// that logging sentinel must not override the actual SDK/retained model.
	if value, ok := opts.Metadata[coreexecutor.RequestedModelMetadataKey]; ok {
		var model string
		switch typed := value.(type) {
		case string:
			model = typed
		case []byte:
			model = string(typed)
		}
		if model = strings.TrimSpace(model); model != "" {
			return model
		}
	}
	if ctx != nil {
		if model, ok := ctx.Value(clientRequestedModelContextKey{}).(string); ok && model != "" {
			return model
		}
	}
	return fallback
}

// ValidateMeteredClientRoute rejects capped keys on transports without shared
// token usage/request admission; silently accepting would bypass daily caps.
func (m *Manager) ValidateMeteredClientRoute(ctx context.Context) error {
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if policy.DailyTokenCap != nil || policy.DailyRequestCap != nil {
			// ponytail: these live transports have neither canonical token usage nor
			// a shared per-generation admission boundary. Do not offer a cap bypass.
			return &Error{Code: "api_key_usage_unavailable", Message: "daily caps require accounted requests; direct Realtime/media or raw HTTP transport is unavailable for capped client keys", HTTPStatus: http.StatusServiceUnavailable}
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
// credential selection. It also checks UTC-day token usage/request admissions.
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
	return m.validateClientDailyCaps(ctx)
}

// AdmitClientRequest charges one logical execution before routing or selection.
// Preserve the returned context for nested SDK calls and retries; separate client
// requests start from their authentication context, not an admitted execution.
// Admitted failures/count/prewarm requests consume a slot; rejected models do not.
func (m *Manager) AdmitClientRequest(ctx context.Context, model string) (context.Context, error) {
	ctx = m.WithClientRequest(ctx, model)
	if err := m.ValidateClientRequest(ctx, model); err != nil {
		return ctx, err
	}
	if m == nil {
		return ctx, nil
	}
	digest, _ := ctx.Value(clientAPIKeyHashContextKey{}).(string)
	if digest == "" {
		return ctx, nil
	}
	u := &m.apiKeyUsage
	u.mu.Lock()
	defer u.mu.Unlock()
	u.todayLocked()
	// An in-flight operation keeps its receipt across UTC rollover; bootstrap
	// retries are not new requests on either day.
	if admission, _ := ctx.Value(clientRequestAdmissionContextKey{}).(*clientRequestAdmission); admission != nil && admission.manager == m && admission.digest == digest {
		return ctx, m.validateDailyCapsLocked(ctx, digest)
	}
	if err := m.validateDailyCapsLocked(ctx, digest); err != nil {
		return ctx, err
	}
	if u.requests[digest] < math.MaxInt64 {
		u.requests[digest]++
	}
	return context.WithValue(ctx, clientRequestAdmissionContextKey{}, &clientRequestAdmission{manager: m, digest: digest, ordinal: u.requests[digest]}), nil
}

func dailyRequestCapError() *Error {
	return &Error{Code: "api_key_daily_request_cap", Message: "client API key daily request cap reached; retry after 00:00 UTC", HTTPStatus: http.StatusTooManyRequests}
}

func (m *Manager) validateClientDailyCaps(ctx context.Context) error {
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
	return m.validateDailyCapsLocked(ctx, digest)
}

// Called with the daily ledger locked; an admitted nth request may finish at N.
func (m *Manager) validateDailyCapsLocked(ctx context.Context, digest string) error {
	u := &m.apiKeyUsage
	admission, _ := ctx.Value(clientRequestAdmissionContextKey{}).(*clientRequestAdmission)
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if policy.DailyTokenCap != nil && u.tokens[digest] >= *policy.DailyTokenCap {
			return &Error{Code: "api_key_daily_token_cap", Message: "client API key daily token cap reached; retry after 00:00 UTC", HTTPStatus: http.StatusTooManyRequests}
		}
		if policy.DailyRequestCap != nil && u.requests[digest] >= *policy.DailyRequestCap {
			if admission == nil || admission.manager != m || admission.digest != digest || admission.ordinal > *policy.DailyRequestCap {
				return dailyRequestCapError()
			}
		}
	}
	return nil
}

func isAPIKeyControlError(err error) bool {
	var policyErr *Error
	return errors.As(err, &policyErr) && (policyErr.Code == "api_key_model_forbidden" || policyErr.Code == "api_key_daily_token_cap" || policyErr.Code == "api_key_daily_request_cap")
}
