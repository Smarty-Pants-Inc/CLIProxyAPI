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
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type keyPolicyContextKey struct{}
type keyPolicyAccount struct {
	gate             chan struct{}
	day              string
	requests, tokens int64
	reserved         int64
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
	reservation              int64
	reservationDay           string
	failed, settled          bool
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
// Restricted clients cannot enter SDK raw execution without policy admission.
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
		a.reserved = 0
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

// BeginKeyPolicy captures the effective authentication/operation floor. The gate
// stays held until settlement; the final send fence reserves the request bound.
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
	// Quota admission and config publication share this lock. A queued operation
	// must retain the policy at this point, not only the one before its wait.
	cfg, _ = m.runtimeConfig.Load().(*config.Config)
	for _, p := range cfg.APIKeyPolicies {
		if p.KeySHA256 == digest {
			policies = append(policies, p)
		}
	}
	policies = copyPolicies(policies)
	m.resetPolicyDay(a)
	var err error
	if cfg.Home.Enabled || cfg.Plugins.Enabled {
		err = policyError("api_key_policy_unavailable", 503)
	}
	for _, p := range policies {
		if p.AllowedModels != nil && !containsExact(*p.AllowedModels, model) {
			err = policyError("api_key_model_forbidden", 403)
		}
		if p.DailyTokenCap != nil && saturatingAdd(a.tokens, a.reserved) >= *p.DailyTokenCap {
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
			defer op.mu.Unlock()
			m.keyPolicyMu.Lock()
			m.resetPolicyDay(a)
			if op.reservationDay == a.day {
				a.reserved -= op.reservation
			}
			a.tokens = saturatingAdd(a.tokens, op.reported)
			// Successful sends without trustworthy usage retain the existing
			// fail-closed behavior. Errors/aborts charge any reported usage only.
			if op.sent && !op.metered && !op.failed && ctx.Err() == nil {
				a.tokens = math.MaxInt64
			}
			op.settled = true
			m.keyPolicyMu.Unlock()
			release()
		})
	}, nil
}

// WithKeyPolicy preserves the admission floor when handlers derive execution contexts.
func WithKeyPolicy(ctx context.Context, op *KeyPolicyOperation) context.Context {
	if op == nil {
		return ctx
	}
	return usage.WithObserver(usage.WithoutPlugins(context.WithValue(translator.WithoutPluginHooks(ctx), keyPolicyContextKey{}, op)), op.observe)
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
	if op.settled {
		return
	}
	op.failed = op.failed || r.Failed
	if r.Detail.InputTokens < 0 || r.Detail.OutputTokens < 0 {
		return
	}
	total := max(saturatingAdd(r.Detail.InputTokens, r.Detail.OutputTokens), r.Detail.TotalTokens, r.Detail.TokenBreakdown.TotalTokens)
	if total > 0 && !r.Detail.Incomplete {
		op.metered = true
	}
	// Retain partial counts for error/abort settlement; cumulative reports
	// may increase, but must never count the same execution twice.
	op.reported = max(op.reported, total)
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

// selectWithCompaction applies unrestricted execution's signer preparation and
// final selected-account check. A policy allow-list is not signer authority.
func (op *KeyPolicyOperation) selectWithCompaction(ctx context.Context, req ex.Request, opts ex.Options) (*Auth, ProviderExecutor, ex.Options, error) {
	if len(opts.OriginalRequest) == 0 {
		opts.OriginalRequest = req.Payload
	}
	opts, err := op.manager.PrepareCompactionRequest(req.Model, opts, ctx)
	if err != nil {
		return nil, nil, opts, err
	}
	a, exec, err := op.selectExecutor(req, opts)
	if err != nil {
		return nil, nil, opts, err
	}
	if err = validateCompactionSelectedAuth(ctx, a.ID, opts); err != nil {
		return nil, nil, opts, err
	}
	return a, exec, opts, nil
}

// The cut deliberately supports only native Codex and Claude HTTP generation. It does not
// enter aliases, plugins, Home, refresh/retry or MarkResult paths.
func (op *KeyPolicyOperation) selectExecutor(req ex.Request, opts ex.Options) (*Auth, ProviderExecutor, error) {
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.settled || op.attempted || req.Model != op.model || opts.Alt != "" {
		return nil, nil, policyError("api_key_policy_unavailable", 503)
	}
	op.attempted = true
	m := op.manager
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	if cfg.Home.Enabled || cfg.Plugins.Enabled {
		return nil, nil, policyError("api_key_policy_unavailable", 503)
	}
	// Signed compaction input may execute only on its signer; never fail over.
	pinned := pinnedAuthIDFromMetadata(opts.Metadata)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, id := range op.policies[0].AllowedAuths {
		a := m.auths[id]
		if (pinned != "" && id != pinned) || a == nil || (a.Provider != "codex" && a.Provider != "claude") || !op.allows(a) || !registry.GetGlobalRegistry().ClientSupportsModel(id, req.Model) {
			continue
		}
		if blocked, _, _ := isAuthBlockedForModel(a, req.Model, time.Now()); blocked {
			continue
		}
		if exec := m.executors[a.Provider]; exec != nil {
			op.selected = a.Clone()
			// Auth.Clone only copies the top-level metadata map. Fence nested secrets too.
			b, err := json.Marshal(op.selected.Metadata)
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
	if pinned != "" {
		return nil, nil, wrapRequestStopError(compactedAuthUnavailableError())
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
	if op.settled || op.sent || selected == nil || !op.allows(selected) {
		return policyError("api_key_policy_unavailable", 503)
	}
	current, ok := op.manager.GetByID(selected.ID)
	blocked, _, _ := isAuthBlockedForModel(current, op.model, time.Now())
	cfg, _ := op.manager.runtimeConfig.Load().(*config.Config)
	if !ok || blocked || current.Provider != selected.Provider || cfg.Home.Enabled || cfg.Plugins.Enabled {
		return policyError("api_key_policy_unavailable", 503)
	}
	currentMetadata, err := json.Marshal(current.Metadata)
	selectedMetadata, snapshotErr := json.Marshal(selected.CloneMetadata())
	if err != nil || snapshotErr != nil || !bytes.Equal(currentMetadata, selectedMetadata) || !reflect.DeepEqual(current.Attributes, selected.Attributes) {
		return policyError("api_key_policy_unavailable", 503)
	}
	token := selected.Attributes["api_key"]
	if token == "" {
		token = selected.MetadataString("access_token")
	}
	account := selected.MetadataString("account_id")
	bearer, apiKey := req.Header.Get("Authorization"), req.Header.Get("X-Api-Key")
	if selected.Provider == "claude" {
		// Claude sends exactly one credential header with exactly one value:
		// x-api-key or a bearer token, never both and never repeated.
		bearers, apiKeys := req.Header.Values("Authorization"), req.Header.Values("X-Api-Key")
		viaBearer := len(bearers) == 1 && bearer == "Bearer "+token && len(apiKeys) == 0
		viaAPIKey := len(apiKeys) == 1 && apiKey == token && len(bearers) == 0
		if token == "" || !(viaBearer || viaAPIKey) {
			return policyError("api_key_policy_unavailable", 503)
		}
	} else if token == "" || bearer != "Bearer "+token || (selected.Attributes["api_key"] == "" && req.Header.Get("Chatgpt-Account-Id") != account) {
		return policyError("api_key_policy_unavailable", 503)
	}
	op.manager.keyPolicyMu.Lock()
	defer op.manager.keyPolicyMu.Unlock()
	op.manager.resetPolicyDay(op.account)
	policies := op.effective()
	for _, p := range policies {
		if p.DailyRequestCap != nil && (*p.DailyRequestCap == 0 || op.account.requests > *p.DailyRequestCap) {
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
	bound := keyPolicyTokenBound(payload, model, selected.Provider)
	used := saturatingAdd(op.account.tokens, op.account.reserved)
	for _, p := range policies {
		if p.DailyTokenCap != nil && (used >= *p.DailyTokenCap || bound > *p.DailyTokenCap-used) {
			return policyError("api_key_daily_token_cap", 429)
		}
	}
	op.reservation = bound
	op.reservationDay = op.account.day
	op.account.reserved = saturatingAdd(op.account.reserved, bound)
	op.sent = true
	return nil
}

// Unknown ceilings fail closed rather than assuming an arbitrary provider limit.
const keyPolicyUnknownTokenBound int64 = math.MaxInt64

// keyPolicyTokenBound reads the final business payload after all translation,
// injection and user payload rules. For byte-tokenized text, the complete JSON
// byte length overestimates input (including framing), unlike a bytes/4 guess.
// Opaque/media inputs instead reserve the entire registered input/context limit.
func keyPolicyTokenBound(payload []byte, model, provider string) int64 {
	var fields map[string]json.RawMessage
	if json.Unmarshal(payload, &fields) != nil {
		return keyPolicyUnknownTokenBound
	}
	output := int64(0)
	for _, name := range []string{"max_tokens", "max_output_tokens", "max_completion_tokens"} {
		if raw, ok := fields[name]; ok {
			var limit int64
			if json.Unmarshal(raw, &limit) != nil || limit <= 0 {
				return keyPolicyUnknownTokenBound
			}
			output = max(output, limit)
		}
	}
	info := registry.LookupModelInfo(model, provider)
	if output == 0 {
		if info == nil {
			return keyPolicyUnknownTokenBound
		}
		output = int64(max(info.MaxCompletionTokens, info.OutputTokenLimit))
		if output <= 0 {
			return keyPolicyUnknownTokenBound
		}
	}
	// A compatible endpoint may support multiple candidates. Never bound only one.
	candidates := int64(1)
	for _, name := range []string{"n", "best_of"} {
		if raw, ok := fields[name]; ok {
			var count int64
			if json.Unmarshal(raw, &count) != nil || count <= 0 {
				return keyPolicyUnknownTokenBound
			}
			candidates = max(candidates, count)
		}
	}
	if output > math.MaxInt64/candidates {
		return keyPolicyUnknownTokenBound
	}
	input := int64(len(payload))
	var body any
	if json.Unmarshal(payload, &body) != nil {
		return keyPolicyUnknownTokenBound
	}
	if keyPolicyOpaqueInput(body) {
		if info == nil || max(info.InputTokenLimit, info.ContextLength, info.MaxContextLength) <= 0 {
			return keyPolicyUnknownTokenBound
		}
		input = max(input, int64(max(info.InputTokenLimit, info.ContextLength, info.MaxContextLength)))
	}
	return saturatingAdd(input, output*candidates)
}

func keyPolicyOpaqueInput(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		if kind, _ := v["type"].(string); kind != "" {
			if strings.HasPrefix(kind, "web_search") || strings.HasPrefix(kind, "web_fetch") || strings.HasPrefix(kind, "file_search") || strings.HasPrefix(kind, "code_execution") {
				return true
			}
			switch kind {
			case "image", "image_url", "input_image", "document", "input_document", "input_file", "file", "input_audio", "audio", "video", "input_video", "video_url", "compaction", "redacted_thinking":
				return true
			}
		}
		for name, child := range v {
			if name == "encrypted_content" || name == "file_id" || name == "image_url" || name == "previous_response_id" || name == "conversation" {
				return true
			}
			if keyPolicyOpaqueInput(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if keyPolicyOpaqueInput(child) {
				return true
			}
		}
	}
	return false
}
