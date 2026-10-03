package access

import (
	"context"
	"net/http"
	"sync"
)

// Manager coordinates authentication providers.
type Manager struct {
	mu        sync.RWMutex
	providers []Provider
	// Fork: denyAll is an authoritative fail-closed gate. SetProviders (for
	// example config reconciliation) never clears it; only SetDenyAll does.
	denyAll bool
}

// SetDenyAll makes Authenticate reject every request until it is cleared.
func (m *Manager) SetDenyAll(deny bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.denyAll = deny
	m.mu.Unlock()
}

// NewManager constructs an empty manager.
func NewManager() *Manager {
	return &Manager{}
}

// SetProviders replaces the active provider list.
func (m *Manager) SetProviders(providers []Provider) {
	if m == nil {
		return
	}
	cloned := make([]Provider, len(providers))
	copy(cloned, providers)
	m.mu.Lock()
	m.providers = cloned
	m.mu.Unlock()
}

// Providers returns a snapshot of the active providers.
func (m *Manager) Providers() []Provider {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	snapshot := make([]Provider, len(m.providers))
	copy(snapshot, m.providers)
	return snapshot
}

// afterAdmissionRead is a test seam: it runs after Authenticate has read the
// admission state and before it evaluates providers. Nil in production.
var afterAdmissionRead func()

// Authenticate evaluates providers until one succeeds.
func (m *Manager) Authenticate(ctx context.Context, r *http.Request) (*Result, *AuthError) {
	if m == nil {
		return nil, nil
	}
	// Fork: read denyAll and the provider list under ONE read lock. Two
	// separate reads could combine an old denyAll=false with a new empty list
	// (a failed Home activation) and admit the request with nil, nil. The lock
	// is released before providers run.
	m.mu.RLock()
	deny := m.denyAll
	providers := make([]Provider, len(m.providers))
	copy(providers, m.providers)
	m.mu.RUnlock()
	if afterAdmissionRead != nil {
		afterAdmissionRead()
	}
	if deny {
		return nil, NewNoCredentialsError()
	}
	if len(providers) == 0 {
		return nil, nil
	}

	var (
		missing bool
		invalid bool
	)

	for _, provider := range providers {
		if provider == nil {
			continue
		}
		res, authErr := provider.Authenticate(ctx, r)
		if authErr == nil {
			return res, nil
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNotHandled) {
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeNoCredentials) {
			missing = true
			continue
		}
		if IsAuthErrorCode(authErr, AuthErrorCodeInvalidCredential) {
			invalid = true
			continue
		}
		return nil, authErr
	}

	if invalid {
		return nil, NewInvalidCredentialError()
	}
	if missing {
		return nil, NewNoCredentialsError()
	}
	return nil, NewNoCredentialsError()
}
