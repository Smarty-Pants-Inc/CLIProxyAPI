package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	log "github.com/sirupsen/logrus"
)

type nativePoolRegistration struct {
	executor ProviderExecutor
	epoch    uint64
}
type nativePoolProof struct {
	identity                          NativePoolIdentity
	binding                           [32]byte
	authEpoch, version, executorEpoch uint64
}
type nativePoolQuarantine struct {
	previousPool          string
	currentPool           string
	authEpoch, generation uint64
}
type nativePoolTransitionWarning struct {
	credentialLabel string
	previousPool    string
	currentPool     string
	generation      string
}
type nativePoolRuntime struct {
	mu             sync.Mutex
	registrations  map[string]nativePoolRegistration
	proofs         map[string]nativePoolProof
	retainedProofs map[string]nativePoolProof
	quarantines    map[string]nativePoolQuarantine
	operations     map[*KeyPolicyOperation]struct{}
	nextEpoch      uint64
	acquisitions   sync.Map
}

var errPoolCredentialQuarantined = errors.New("native pool credential quarantined")

// RegisterNativePoolExecutor is an explicit trusted-composition boundary. Merely
// implementing NativePoolIdentityAcquirer never opts an ordinary executor in.
func (m *Manager) RegisterNativePoolExecutor(exec ProviderExecutor) error {
	if m == nil || exec == nil {
		return poolError("path_unavailable", 503)
	}
	provider := exec.Identifier()
	if provider != "codex" && provider != "claude" {
		return poolError("path_unavailable", 503)
	}
	if _, ok := exec.(NativePoolIdentityAcquirer); !ok {
		return poolError("identity_unverified", 503)
	}
	m.RegisterExecutor(exec)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.executors[provider] != exec {
		return poolError("identity_unverified", 503)
	}
	r := &m.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.registrations == nil {
		r.registrations = make(map[string]nativePoolRegistration)
	}
	r.nextEpoch++
	r.registrations[provider] = nativePoolRegistration{exec, r.nextEpoch}
	return nil
}

func poolError(code string, status int) error { return policyError("api_key_pool_"+code, status) }
func clonePoolIdentity(i NativePoolIdentity) NativePoolIdentity {
	i.AccountAliases = maps.Clone(i.AccountAliases)
	return i
}

func normalizePoolIdentity(i NativePoolIdentity) (NativePoolIdentity, error) {
	i = clonePoolIdentity(i)
	if i.Provider != "codex" && i.Provider != "claude" {
		return i, poolError("identity_unverified", 503)
	}
	for _, s := range append([]string{i.AccountID, i.EntitlementID}, mapValues(i.AccountAliases)...) {
		if s == "" || len(s) > 256 || strings.TrimSpace(s) != s || strings.ContainsFunc(s, unicode.IsControl) {
			return i, poolError("identity_unverified", 503)
		}
	}
	if i.Provider == "claude" {
		a, errA := uuid.Parse(i.AccountID)
		e, errE := uuid.Parse(i.EntitlementID)
		if errA != nil || errE != nil || a == uuid.Nil || e == uuid.Nil {
			return i, poolError("identity_unverified", 503)
		}
		i.AccountID, i.EntitlementID = a.String(), e.String()
	}
	return i, nil
}
func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func poolIdentityOwnerForRuntime(raw any, identity NativePoolIdentity) (string, error) {
	cfg, _ := raw.(*config.Config)
	return poolIdentityOwner(cfg, identity)
}

func logPoolTransitionWarning(warning *nativePoolTransitionWarning) {
	if warning == nil {
		return
	}
	log.WithFields(log.Fields{
		"credential_label":      warning.credentialLabel,
		"old_pool":              warning.previousPool,
		"new_pool":              warning.currentPool,
		"credential_generation": warning.generation,
	}).Warn("native credential identity moved between pools; credential quarantined")
}

// Caller holds the manager and pool runtime locks. This repeats the historical
// quarantine cause for a new credential generation; it does not acquire proof.
func (m *Manager) poolTransitionWarningLocked(a *Auth) *nativePoolTransitionWarning {
	r := &m.poolRuntime
	q := r.quarantines[a.ID]
	if q.authEpoch == a.RegistrationEpoch && q.generation == a.CredentialVersion {
		return nil
	}
	q.authEpoch, q.generation = a.RegistrationEpoch, a.CredentialVersion
	r.quarantines[a.ID] = q
	return &nativePoolTransitionWarning{
		credentialLabel: a.Label,
		previousPool:    q.previousPool,
		currentPool:     q.currentPool,
		generation:      fmt.Sprintf("%d:%d", q.authEpoch, q.generation),
	}
}

func (m *Manager) poolCredentialQuarantined(id string) bool {
	if m == nil || id == "" {
		return false
	}
	r := &m.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.quarantines[id]
	return ok
}

// The private binding covers native credentials, source classification, and
// account/header authority inputs, including nested credential metadata.
// It is never serialized or returned to callers.
func poolCredentialBinding(a *Auth) [32]byte {
	if a == nil {
		return [32]byte{}
	}
	material := map[string]any{}
	for _, key := range []string{"access_token", "refresh_token", "id_token", "account_id", "account_uuid", "organization_uuid", "claudeAiOauth", "auth_kind", "is_setup_token", "setup_token", "skip_account_profile", "scopes", "scope"} {
		if value, ok := a.MetadataValue(key); ok {
			material[key] = value
		}
	}
	b, err := json.Marshal(struct {
		Provider   string
		Attributes map[string]string
		Material   map[string]any
		Proxy      string
	}{a.Provider, a.Attributes, material, a.ProxyURL})
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(b)
}
func proofMatches(p nativePoolProof, a *Auth, r nativePoolRegistration) bool {
	return a != nil && p.authEpoch == a.RegistrationEpoch && p.version == a.CredentialVersion && p.executorEpoch == r.epoch && r.executor != nil && p.binding != [32]byte{} && p.binding == poolCredentialBinding(a)
}

// acquirePoolProof serializes by credential ID, publishes only against the exact
// captured generation, and never gives unproven candidates business authority.
// A cross-pool identity transition is retained as a quarantine rather than being
// reported as an unknown identity, so other proven credentials can continue.
func (m *Manager) acquirePoolProof(ctx context.Context, candidate *Auth) (*Auth, nativePoolProof, error) {
	var zero nativePoolProof
	if candidate == nil {
		return nil, zero, poolError("identity_unverified", 503)
	}
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	v, _ := m.poolRuntime.acquisitions.LoadOrStore(candidate.ID, &sync.Mutex{})
	lock := v.(*sync.Mutex)
	lock.Lock()
	// Identity acquisition can rotate refresh tokens too. Share the ordinary
	// refresh lock and read the current credential only after both locks are held.
	refreshValue, _ := m.refreshLocks.LoadOrStore(candidate.ID, &authRefreshLock{})
	refreshLock := refreshValue.(*authRefreshLock)
	refreshLock.mu.Lock()
	var warning *nativePoolTransitionWarning
	defer func() {
		refreshLock.mu.Unlock()
		lock.Unlock()
		logPoolTransitionWarning(warning)
	}()
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	m.mu.RLock()
	current := m.auths[candidate.ID]
	if !nativePoolCandidate(current) {
		m.mu.RUnlock()
		return nil, zero, poolError("identity_unverified", 503)
	}
	current = current.Clone()
	rt := &m.poolRuntime
	rt.mu.Lock()
	if _, quarantined := rt.quarantines[current.ID]; quarantined {
		warning = m.poolTransitionWarningLocked(current)
		rt.mu.Unlock()
		m.mu.RUnlock()
		return nil, zero, errPoolCredentialQuarantined
	}
	r := rt.registrations[current.Provider]
	p, proven := rt.proofs[current.ID]
	// Active proofs may be complete but unowned. Only the last configured
	// owner supplies transition lineage, even across cache invalidation.
	previous, retained := rt.retainedProofs[current.ID]
	rt.mu.Unlock()
	m.mu.RUnlock()
	accessToken := current.MetadataString("access_token")
	forceRefresh := (candidate.RejectedAccessToken != "" && candidate.RejectedAccessToken == accessToken) || (current.RejectedAccessToken != "" && current.RejectedAccessToken == accessToken)
	if expiry, hasExpiry := current.AccessTokenExpirationTime(); hasExpiry && !expiry.IsZero() && !expiry.After(time.Now()) {
		forceRefresh = true
	}
	if proven && proofMatches(p, current, r) && !forceRefresh {
		return current, p, nil
	}
	acquirer, ok := r.executor.(NativePoolIdentityAcquirer)
	if !ok {
		return nil, zero, poolError("identity_unverified", 503)
	}
	target := current.Clone()
	if forceRefresh {
		target.RejectedAccessToken = current.MetadataString("access_token")
	}
	updated, identity, err := acquirer.AcquirePoolIdentity(ctx, target)
	if err != nil {
		if ctx.Err() != nil {
			return nil, zero, ctx.Err()
		}
		return nil, zero, poolError("identity_unverified", 503)
	}
	identity, err = normalizePoolIdentity(identity)
	if err != nil || updated == nil || updated.ID != current.ID || identity.Provider != current.Provider || !nativePoolCandidate(updated) {
		return nil, zero, poolError("identity_unverified", 503)
	}
	// UpdateRefreshedAuth owns the existing auth mutation serialization and rejects
	// raced material/registration replacement. Compare exact returned material too.
	published, err := m.UpdateRefreshedAuth(ctx, current, updated)
	if err != nil || published == nil || poolCredentialBinding(published) != poolCredentialBinding(updated) {
		return nil, zero, poolError("identity_unverified", 503)
	}
	m.mu.RLock()
	latest := m.auths[current.ID]
	rt.mu.Lock()
	if rt.registrations[current.Provider] != r || latest == nil || latest.RegistrationEpoch != published.RegistrationEpoch || latest.CredentialVersion != published.CredentialVersion || poolCredentialBinding(latest) != poolCredentialBinding(published) {
		rt.mu.Unlock()
		m.mu.RUnlock()
		return nil, zero, poolError("identity_unverified", 503)
	}
	p = nativePoolProof{clonePoolIdentity(identity), poolCredentialBinding(latest), latest.RegistrationEpoch, latest.CredentialVersion, r.epoch}
	if rt.proofs == nil {
		rt.proofs = make(map[string]nativePoolProof)
	}
	newPool, newErr := poolIdentityOwnerForRuntime(m.runtimeConfig.Load(), identity)
	if newErr != nil {
		rt.mu.Unlock()
		m.mu.RUnlock()
		return nil, zero, poolError("identity_unverified", 503)
	}
	if retained {
		oldPool, oldErr := poolIdentityOwnerForRuntime(m.runtimeConfig.Load(), previous.identity)
		if oldErr != nil {
			rt.mu.Unlock()
			m.mu.RUnlock()
			return nil, zero, poolError("identity_unverified", 503)
		}
		if oldPool != "" && newPool != "" && oldPool != newPool && !samePoolIdentity(previous.identity, identity) {
			if rt.quarantines == nil {
				rt.quarantines = make(map[string]nativePoolQuarantine)
			}
			if _, already := rt.quarantines[current.ID]; !already {
				rt.quarantines[current.ID] = nativePoolQuarantine{previousPool: oldPool, currentPool: newPool}
				delete(rt.proofs, current.ID)
				m.cancelPoolAuthOperationsLocked(current.ID)
				warning = m.poolTransitionWarningLocked(latest)
				rt.mu.Unlock()
				m.mu.RUnlock()
				return nil, zero, errPoolCredentialQuarantined
			}
		}
	}
	rt.proofs[current.ID] = p
	if newPool != "" {
		if rt.retainedProofs == nil {
			rt.retainedProofs = make(map[string]nativePoolProof)
		}
		rt.retainedProofs[current.ID] = p
	}
	rt.mu.Unlock()
	m.mu.RUnlock()
	return latest.Clone(), p, nil
}
func nativePoolCandidate(a *Auth) bool {
	return a != nil && !a.Disabled && a.Status != StatusDisabled && (a.Provider == "codex" || a.Provider == "claude") && a.AuthKind() == "oauth" && a.Attributes["api_key"] == "" && a.Attributes["base_url"] == "" && (a.MetadataString("access_token") != "" || a.MetadataString("refresh_token") != "")
}

func (m *Manager) clearNativePoolTrustLocked(provider string) {
	r := &m.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.registrations, provider)
	// Publication already retained the last configured owner. Invalidating an
	// active unowned proof must not replace that lineage.
	for id, p := range r.proofs {
		if p.identity.Provider == provider {
			delete(r.proofs, id)
		}
	}
	for op := range r.operations {
		want := "codex"
		if op.pool.kind == PoolMessages || op.pool.kind == PoolCountTokens {
			want = "claude"
		}
		if want == provider {
			op.pool.cancel()
		}
	}
}
