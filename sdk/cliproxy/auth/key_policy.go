package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type keyPolicyContextKey struct{}
type keyPolicyAccount struct {
	gate             chan struct{}
	day              string
	requests, tokens int64
}
type KeyPolicyOperation struct {
	manager                  *Manager
	policies                 []config.APIKeyPolicy
	account                  *keyPolicyAccount
	model                    string
	selected                 *Auth
	mu                       sync.Mutex
	attempted, sent, metered bool
	reported                 int64
	streamDone               <-chan struct{}
}

func keyDigest(key string) string { b := sha256.Sum256([]byte(key)); return hex.EncodeToString(b[:]) }
func copyPolicies(p []config.APIKeyPolicy) []config.APIKeyPolicy {
	return (&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: p}}).CloneForRuntime().APIKeyPolicies
}
func (m *Manager) KeyPolicies(key string) []config.APIKeyPolicy {
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	var out []config.APIKeyPolicy
	for _, p := range cfg.APIKeyPolicies {
		if p.KeySHA256 == keyDigest(key) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return copyPolicies(out)
}

// ponytail: reuse the authenticated principal, never re-read competing client headers.
// This also fences sockets opened before a policy was enabled on their key.
func (m *Manager) MissingKeyPolicy(ctx context.Context) bool {
	if m == nil || ctx == nil || KeyPolicyFromContext(ctx) != nil {
		return false
	}
	c, _ := ctx.Value("gin").(*gin.Context)
	return c != nil && len(m.KeyPolicies(c.GetString("userApiKey"))) != 0
}
func policyError(code string, status int) error {
	return &Error{Code: code, Message: code, HTTPStatus: status}
}
func (m *Manager) policyDay() string {
	now := time.Now()
	if m.keyPolicyNow != nil {
		now = m.keyPolicyNow()
	}
	return now.UTC().Format("2006-01-02")
}
func (m *Manager) resetPolicyDay(a *keyPolicyAccount) {
	if day := m.policyDay(); a.day != day {
		a.day = day
		a.requests = 0
		a.tokens = 0
	}
}
func containsExact(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// BeginKeyPolicy captures the effective authentication/operation floor. One active
// operation per key bounds token overshoot to one operation, independent of callers.
func (m *Manager) BeginKeyPolicy(ctx context.Context, policies []config.APIKeyPolicy, model string) (context.Context, func(), error) {
	if len(policies) == 0 {
		return ctx, func() {}, nil
	}
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	policies = append([]config.APIKeyPolicy(nil), policies...)
	for _, p := range cfg.APIKeyPolicies {
		if p.KeySHA256 == policies[0].KeySHA256 {
			policies = append(policies, p)
		}
	}
	policies = copyPolicies(policies)
	if cfg.Home.Enabled || cfg.Plugins.Enabled || ex.DownstreamWebsocket(ctx) || ex.RequiredUpstreamWebsocket(ctx) {
		return ctx, nil, policyError("api_key_policy_unavailable", 503)
	}
	for _, p := range policies {
		if p.AllowedModels != nil && !containsExact(*p.AllowedModels, model) {
			return ctx, nil, policyError("api_key_model_forbidden", 403)
		}
	}
	m.keyPolicyMu.Lock()
	if m.keyPolicyAccounts == nil {
		m.keyPolicyAccounts = map[string]*keyPolicyAccount{}
	}
	digest := policies[0].KeySHA256
	a := m.keyPolicyAccounts[digest]
	if a == nil {
		a = &keyPolicyAccount{gate: make(chan struct{}, 1)}
		m.keyPolicyAccounts[digest] = a
	}
	m.keyPolicyMu.Unlock()
	select {
	case a.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx, nil, ctx.Err()
	}
	release := func() { <-a.gate }
	m.keyPolicyMu.Lock()
	m.resetPolicyDay(a)
	var err error
	for _, p := range policies {
		if p.DailyTokenCap != nil && a.tokens >= *p.DailyTokenCap {
			err = policyError("api_key_daily_token_cap", 429)
		}
		if p.DailyRequestCap != nil && a.requests >= *p.DailyRequestCap {
			err = policyError("api_key_daily_request_cap", 429)
		}
	}
	if err == nil {
		a.requests = saturatingAdd(a.requests, 1)
	}
	m.keyPolicyMu.Unlock()
	if err != nil {
		release()
		return ctx, nil, err
	}
	op := &KeyPolicyOperation{manager: m, account: a, policies: policies, model: model}
	ctx = WithKeyPolicy(ctx, op)
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			if op.streamDone != nil {
				<-op.streamDone
			}
			op.mu.Lock()
			missing := op.sent && !op.metered
			op.mu.Unlock()
			if missing {
				m.keyPolicyMu.Lock()
				m.resetPolicyDay(a)
				a.tokens = math.MaxInt64
				m.keyPolicyMu.Unlock()
			}
			release()
		})
	}, nil
}

// WithKeyPolicy preserves the admission floor when handlers derive execution contexts.
func WithKeyPolicy(ctx context.Context, op *KeyPolicyOperation) context.Context {
	if op == nil {
		return ctx
	}
	return usage.WithObserver(context.WithValue(translator.WithoutPluginHooks(ctx), keyPolicyContextKey{}, op), op.observe)
}
func KeyPolicyFromContext(ctx context.Context) *KeyPolicyOperation {
	if ctx == nil {
		return nil
	}
	op, _ := ctx.Value(keyPolicyContextKey{}).(*KeyPolicyOperation)
	return op
}
func saturatingAdd(a, b int64) int64 {
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}
func (op *KeyPolicyOperation) observe(r usage.Record) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if r.Detail.InputTokens < 0 || r.Detail.OutputTokens < 0 {
		return
	}
	total := max(saturatingAdd(r.Detail.InputTokens, r.Detail.OutputTokens), r.Detail.TotalTokens, r.Detail.TokenBreakdown.TotalTokens)
	if total == 0 {
		return
	}
	op.metered = true
	// Exactly one execution: cumulative usage may increase, never count twice.
	previous := op.reported
	if total <= previous {
		return
	}
	op.reported = total
	op.manager.keyPolicyMu.Lock()
	defer op.manager.keyPolicyMu.Unlock()
	op.manager.resetPolicyDay(op.account)
	op.account.tokens = saturatingAdd(op.account.tokens, total-previous)
}
func (op *KeyPolicyOperation) effective() []config.APIKeyPolicy {
	out := append([]config.APIKeyPolicy(nil), op.policies...)
	cfg, _ := op.manager.runtimeConfig.Load().(*config.Config)
	for _, p := range cfg.APIKeyPolicies {
		if p.KeySHA256 == out[0].KeySHA256 {
			out = append(out, p)
		}
	}
	return out
}
func (op *KeyPolicyOperation) allows(a *Auth) bool {
	for _, p := range op.effective() {
		if !containsExact(p.AllowedAuths, a.ID) || (p.AllowedModels != nil && !containsExact(*p.AllowedModels, op.model)) {
			return false
		}
	}
	return true
}

// The cut deliberately supports only native Codex HTTP generation. It does not
// enter aliases, plugins, Home, preparation, refresh/retry or MarkResult paths.
func (op *KeyPolicyOperation) selectExecutor(req ex.Request, opts ex.Options) (*Auth, ProviderExecutor, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.attempted || req.Model != op.model || opts.Alt != "" {
		return nil, nil, policyError("api_key_policy_unavailable", 503)
	}
	op.attempted = true
	m := op.manager
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	if cfg.Home.Enabled || cfg.Plugins.Enabled {
		return nil, nil, policyError("api_key_policy_unavailable", 503)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, id := range op.policies[0].AllowedAuths {
		a := m.auths[id]
		if a == nil || a.Provider != "codex" || !op.allows(a) || !registry.GetGlobalRegistry().ClientSupportsModel(id, req.Model) {
			continue
		}
		if blocked, _, _ := isAuthBlockedForModel(a, req.Model, time.Now()); blocked {
			continue
		}
		if exec := m.executors["codex"]; exec != nil {
			op.selected = a.Clone()
			// Auth.Clone only copies the top-level metadata map. Fence nested secrets too.
			b, err := json.Marshal(a.Metadata)
			if err != nil {
				return nil, nil, policyError("api_key_policy_unavailable", 503)
			}
			op.selected.Metadata = nil
			if json.Unmarshal(b, &op.selected.Metadata) != nil {
				return nil, nil, policyError("api_key_policy_unavailable", 503)
			}
			return op.selected, exec, nil
		}
	}
	return nil, nil, policyError("api_key_policy_unavailable", 503)
}

// CheckKeyPolicySend binds the final model and published credential snapshot and
// forbids redirects/replays. Runtime policy relaxation cannot erase admission.
func CheckKeyPolicySend(req *http.Request) error {
	op := KeyPolicyFromContext(req.Context())
	if op == nil {
		return nil
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	selected := op.selected
	if op.sent || selected == nil || !op.allows(selected) {
		return policyError("api_key_policy_unavailable", 503)
	}
	current, ok := op.manager.GetByID(selected.ID)
	blocked, _, _ := isAuthBlockedForModel(current, op.model, time.Now())
	cfg, _ := op.manager.runtimeConfig.Load().(*config.Config)
	if !ok || blocked || current.Provider != selected.Provider || cfg.Home.Enabled || cfg.Plugins.Enabled {
		return policyError("api_key_policy_unavailable", 503)
	}
	currentMetadata, err := json.Marshal(current.Metadata)
	selectedMetadata, snapshotErr := json.Marshal(selected.Metadata)
	if err != nil || snapshotErr != nil || !bytes.Equal(currentMetadata, selectedMetadata) || !reflect.DeepEqual(current.Attributes, selected.Attributes) {
		return policyError("api_key_policy_unavailable", 503)
	}
	token := selected.Attributes["api_key"]
	if token == "" {
		token, _ = selected.Metadata["access_token"].(string)
	}
	account, _ := selected.Metadata["account_id"].(string)
	if token == "" || req.Header.Get("Authorization") != "Bearer "+token || (selected.Attributes["api_key"] == "" && req.Header.Get("Chatgpt-Account-Id") != account) {
		return policyError("api_key_policy_unavailable", 503)
	}
	op.manager.keyPolicyMu.Lock()
	defer op.manager.keyPolicyMu.Unlock()
	op.manager.resetPolicyDay(op.account)
	for _, p := range op.effective() {
		if (p.DailyRequestCap != nil && (*p.DailyRequestCap == 0 || op.account.requests > *p.DailyRequestCap)) || (p.DailyTokenCap != nil && op.account.tokens >= *p.DailyTokenCap) {
			return policyError("api_key_daily_cap", 429)
		}
	}
	payload, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(payload))
	if err != nil {
		return err
	}
	model, err := ex.PolicyModel(payload)
	if err != nil || model != op.model {
		return policyError("api_key_model_forbidden", 403)
	}
	op.sent = true
	return nil
}
