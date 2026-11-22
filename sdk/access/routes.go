package access

import (
	"net/http"
	"strings"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// RouteKeyDigestsContextKey carries manager-verified route attribution to delegated credentials.
const RouteKeyDigestsContextKey = "accessRouteKeyDigests"

// SetProvidersAndAPIKeyRoutes atomically publishes providers and an immutable route snapshot.
// SetProviders, used by plugin refreshes, deliberately leaves this snapshot intact.
func (m *Manager) SetProvidersAndAPIKeyRoutes(providers []Provider, routes []config.APIKeyRoute) {
	if m == nil {
		return
	}
	clonedProviders := append([]Provider(nil), providers...)
	clonedRoutes := make(map[string]config.APIKeyRoute, len(routes))
	for _, route := range routes {
		route.Allow = append([]string(nil), route.Allow...)
		clonedRoutes[route.KeySHA256] = route
	}
	m.mu.Lock()
	m.providers, m.routes = clonedProviders, clonedRoutes
	m.mu.Unlock()
}

// RequestHasRouteKey reports whether a supplied client credential is route-scoped.
// Optional-auth transports use this to retain their anonymous/unrestricted bypass
// without allowing an explicitly supplied restricted credential to bypass enforcement.
func (m *Manager) RequestHasRouteKey(r *http.Request) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	routes := m.routes
	m.mu.RUnlock()
	for _, key := range requestKeyCandidates(r) {
		if _, exists := routes[internalconfig.APIKeyDigest(key)]; key != "" && exists {
			return true
		}
	}
	return false
}

// AuthorizeAPIKeyRoutes checks an already authenticated issuer's current route policy.
// It does not authenticate the key and must only be used after delegated credentials
// have been verified by their own authenticator.
func (m *Manager) AuthorizeAPIKeyRoutes(principal string, r *http.Request) *AuthError {
	if m == nil || principal == "" {
		return nil
	}
	return m.AuthorizeRouteKeyDigests([]string{internalconfig.APIKeyDigest(principal)}, r)
}

// AuthorizeRouteKeyDigests checks trusted issuer attribution against the current snapshot.
// Removing a route entry restores unrestricted behavior, including for existing delegates.
func (m *Manager) AuthorizeRouteKeyDigests(digests []string, r *http.Request) *AuthError {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	routes := m.routes
	m.mu.RUnlock()
	for _, digest := range digests {
		if route, exists := routes[digest]; exists && !requestMatchesRoute(route, r) {
			return NewAPIKeyRouteDeniedError()
		}
	}
	return nil
}

func authorizeRequestRoutes(routes map[string]config.APIKeyRoute, principal string, r *http.Request, credentialPrincipal bool) ([]string, *AuthError) {
	candidates := requestKeyCandidates(r)
	// The config provider returns the actual credential that won its candidate
	// order. Do not apply a rejected credential's rules to that successful key.
	// Other providers can map identities; neither their principal nor arbitrary
	// source metadata proves which request credential authenticated the request.
	identified := false
	if credentialPrincipal {
		for _, candidate := range candidates {
			if principal != "" && candidate == principal {
				identified = true
				break
			}
		}
	}
	// Plugins may return an account identity instead of a key, including when
	// exclusive and the config provider never runs. No candidate is proven to
	// be the winning key: retain every supplied restriction, not plugin metadata.
	// With no candidates there is no client-key attribution; never substitute
	// the mapped account, which may coincide with another client's key.
	keys := candidates
	if identified {
		keys = []string{principal}
	}
	var digests []string
	seen := make(map[string]struct{})
	for _, key := range keys {
		if key == "" {
			continue
		}
		digest := internalconfig.APIKeyDigest(key)
		if route, exists := routes[digest]; exists && !requestMatchesRoute(route, r) {
			return nil, NewAPIKeyRouteDeniedError()
		}
		if _, duplicate := seen[digest]; !duplicate {
			seen[digest] = struct{}{}
			digests = append(digests, digest)
		}
	}
	return digests, nil
}

func requestMatchesRoute(route config.APIKeyRoute, r *http.Request) bool {
	return r != nil && r.URL != nil && route.Matches(r.Method, r.URL.Path)
}

// Keep the values and ordering identical to config_access.provider.Authenticate.
// Do not trim header/query keys: only Bearer token parsing trims its token.
func requestKeyCandidates(r *http.Request) []string {
	if r == nil {
		return nil
	}
	authorization := r.Header.Get("Authorization")
	if parts := strings.SplitN(authorization, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		authorization = strings.TrimSpace(parts[1])
	}
	keys := []string{authorization, r.Header.Get("X-Goog-Api-Key"), r.Header.Get("X-Api-Key")}
	if r.URL != nil {
		keys = append(keys, r.URL.Query().Get("key"), r.URL.Query().Get("auth_token"))
	}
	return keys
}
