package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path"
	"path/filepath"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type clientAPIKeyHashContextKey struct{}
type apiKeyPoliciesContextKey struct{}
type apiKeyAdmissionPoliciesContextKey struct{}

// WithClientAPIKey binds an authenticated client principal to a request. Call this
// only after authentication, never with an unverified header or request metadata.
// Only the digest is retained. Provider credentials and Home replies cannot change it.
func WithClientAPIKey(ctx context.Context, key string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	digest := sha256.Sum256([]byte(key))
	return context.WithValue(ctx, clientAPIKeyHashContextKey{}, hex.EncodeToString(digest[:]))
}

// WithClientAPIKeyPolicies binds the admission-time policy snapshot. Later
// removal or relaxation must not make an admitted request or derived token unrestricted.
func WithClientAPIKeyPolicies(ctx context.Context, key string, policies []internalconfig.APIKeyPolicy) context.Context {
	ctx = WithClientAPIKey(ctx, key)
	digest, _ := ctx.Value(clientAPIKeyHashContextKey{}).(string)
	var matched []internalconfig.APIKeyPolicy
	for _, policy := range policies {
		if strings.EqualFold(strings.TrimSpace(policy.KeySHA256), digest) {
			matched = append(matched, policy)
		}
	}
	snapshot := (&internalconfig.Config{SDKConfig: internalconfig.SDKConfig{APIKeyPolicies: matched}}).CloneForRuntime()
	return context.WithValue(ctx, apiKeyAdmissionPoliciesContextKey{}, snapshot.APIKeyPolicies)
}

// WithClientAPIKeyFromContext preserves authenticated identity when a handler uses
// a different cancellation parent (including long-lived websocket contexts).
func WithClientAPIKeyFromContext(ctx, source context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if source != nil {
		if digest, ok := source.Value(clientAPIKeyHashContextKey{}).(string); ok {
			ctx = context.WithValue(ctx, clientAPIKeyHashContextKey{}, digest)
			if policies, ok := source.Value(apiKeyAdmissionPoliciesContextKey{}).([]internalconfig.APIKeyPolicy); ok {
				ctx = context.WithValue(ctx, apiKeyAdmissionPoliciesContextKey{}, policies)
			}
			if model, ok := source.Value(clientRequestedModelContextKey{}).(string); ok {
				ctx = context.WithValue(ctx, clientRequestedModelContextKey{}, model)
			}
			if admission, ok := source.Value(clientRequestAdmissionContextKey{}).(*clientRequestAdmission); ok {
				ctx = context.WithValue(ctx, clientRequestAdmissionContextKey{}, admission)
			}
			ctx = cliproxyexecutor.WithClientExecutionPolicyFromContext(ctx, source)
			return coreusage.WithRecordObserverFromContext(ctx, source)
		}
	}
	return ctx
}

func (m *Manager) withAPIKeyPolicies(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	digest, _ := ctx.Value(clientAPIKeyHashContextKey{}).(string)
	admitted, _ := ctx.Value(apiKeyAdmissionPoliciesContextKey{}).([]internalconfig.APIKeyPolicy)
	policies := append([]internalconfig.APIKeyPolicy(nil), admitted...)
	if m != nil && digest != "" {
		cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
		if cfg != nil {
			for _, policy := range cfg.APIKeyPolicies {
				if strings.EqualFold(strings.TrimSpace(policy.KeySHA256), digest) {
					policies = append(policies, policy)
				}
			}
		}
	}
	return context.WithValue(ctx, apiKeyPoliciesContextKey{}, policies)
}

func apiKeyPoliciesFromContext(ctx context.Context) []internalconfig.APIKeyPolicy {
	if ctx == nil {
		return nil
	}
	policies, _ := ctx.Value(apiKeyPoliciesContextKey{}).([]internalconfig.APIKeyPolicy)
	return policies
}

func apiKeyPolicyAllows(policy internalconfig.APIKeyPolicy, auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(policy.AllowedProviders) > 0 {
		allowed := false
		for _, provider := range policy.AllowedProviders {
			if strings.EqualFold(strings.TrimSpace(provider), strings.TrimSpace(auth.Provider)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	// Only credential file names and explicit email metadata are identities. Labels,
	// provider names and arbitrary IDs must not broaden the allowlist.
	identities := []string{auth.FileName, auth.Attributes["email"]}
	if email, ok := auth.Metadata["email"].(string); ok {
		identities = append(identities, email)
	}
	for _, pattern := range policy.AllowedAuths {
		for _, identity := range identities {
			if identity == "" {
				continue
			}
			if identity == auth.FileName {
				identity = filepath.Base(identity)
			}
			if matched, err := path.Match(pattern, identity); err == nil && matched {
				return true
			}
		}
	}
	return false
}

func apiKeyPolicyUnavailableError() *Error {
	return &Error{Code: "api_key_policy_unavailable", Message: "no credential available within the client API key allowlist", HTTPStatus: http.StatusServiceUnavailable}
}

// ValidateClientAuth checks the current policy at direct execution boundaries,
// including pinned credentials, refresh/preparation and retained websocket auths.
func (m *Manager) ValidateClientAuth(ctx context.Context, auth *Auth) error {
	if ctx != nil {
		if model, ok := ctx.Value(clientRequestedModelContextKey{}).(string); ok {
			if err := m.ValidateClientRequest(ctx, model); err != nil {
				return err
			}
		} else if err := m.validateClientDailyCaps(ctx); err != nil {
			return err
		}
	}
	for _, policy := range apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx)) {
		if !apiKeyPolicyAllows(policy, auth) {
			return apiKeyPolicyUnavailableError()
		}
	}
	return nil
}

// HasConfiguredAPIKeyPolicies keeps native callback context admission fail-closed
// after policy removal: outstanding restricted invocations may still exist.
func (m *Manager) HasConfiguredAPIKeyPolicies() bool {
	return m != nil && m.apiKeyPoliciesConfigured.Load()
}

// HasAPIKeyPolicies reports whether request authentication is required for a configured boundary.
func (m *Manager) HasAPIKeyPolicies() bool {
	if m == nil {
		return false
	}
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	return cfg != nil && len(cfg.APIKeyPolicies) > 0
}

// HasClientAPIKeyPolicy reports whether an authenticated client is restricted.
// Routes without a selectable credential must fail closed for these clients.
func (m *Manager) HasClientAPIKeyPolicy(ctx context.Context) bool {
	return len(apiKeyPoliciesFromContext(m.withAPIKeyPolicies(ctx))) > 0
}

// Retained sockets must validate the immutable credential used to dial, as well
// as the handler's current record. Re-registering the same ID cannot bless it.
func (m *Manager) contextWithClientAuthCheck(ctx context.Context, selected *Auth) context.Context {
	bound := selected.Clone()
	result := cliproxyexecutor.WithWebsocketRequestCheck(ctx, func(model string) error {
		if model == "" {
			model, _ = ctx.Value(clientRequestedModelContextKey{}).(string)
		}
		return m.ValidateClientRequest(ctx, model)
	})
	result = cliproxyexecutor.WithWebsocketAdmittedRequestCheck(result, func(admitted context.Context, model string) error {
		if model == "" {
			model = ClientRequestedModelFromContext(admitted)
		}
		return m.ValidateClientRequest(admitted, model)
	})
	result = cliproxyexecutor.WithWebsocketRequestAdmission(result, func(model string) (context.Context, error) {
		if model == "" {
			model = ClientRequestedModelFromContext(ctx)
		}
		fresh := context.WithValue(ctx, clientRequestAdmissionContextKey{}, (*clientRequestAdmission)(nil))
		fresh = cliproxyexecutor.WithoutClientExecutionPolicy(fresh)
		return m.AdmitClientRequest(fresh, model)
	})
	if m.HasClientAPIKeyPolicy(ctx) {
		result = cliproxyexecutor.WithWebsocketCredentialBinding(result)
	}
	return cliproxyexecutor.WithWebsocketContextAuthCheck(result, func(admitted context.Context, id string) bool {
		current := WithClientAPIKeyFromContext(ctx, admitted)
		return bound != nil && id == bound.ID && m.ValidateClientAuth(current, bound) == nil && cliproxyexecutor.WebsocketAuthEnabled(current, id)
	})
}

func (m *Manager) validatePreparedClientAuth(ctx context.Context, prepared **Auth, err *error) {
	if *err == nil {
		*err = m.ValidateClientAuth(ctx, *prepared)
	}
}

func (m *Manager) validateAPIKeySelection(ctx context.Context, selected **Auth, err *error) {
	if *err == nil {
		*err = m.ValidateClientAuth(ctx, *selected)
	}
	*err = apiKeySelectionError(ctx, *err)
	if *err != nil {
		*selected = nil
	}
}

func apiKeySelectionError(ctx context.Context, err error) error {
	if err == nil || len(apiKeyPoliciesFromContext(ctx)) == 0 || isRequestTerminatedError(err) || isAPIKeyControlError(err) {
		return err
	}
	if statusCodeFromError(err) == http.StatusTooManyRequests {
		return err
	}
	return apiKeyPolicyUnavailableError()
}
