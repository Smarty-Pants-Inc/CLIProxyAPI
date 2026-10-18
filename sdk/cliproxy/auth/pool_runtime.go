package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func (m *Manager) poolPrincipalLocked(key string) (config.AccountPool, []config.APIKeyPolicy, error) {
	var zero config.AccountPool
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	if cfg == nil || cfg.AccountPools == nil || m.poolInvalid.Load() {
		return zero, nil, poolError("admission_required", 503)
	}
	if key == "" || !containsExact(cfg.APIKeys, key) {
		return zero, nil, poolError("unclassified", 403)
	}
	var policies []config.APIKeyPolicy
	for _, p := range cfg.APIKeyPolicies {
		if p.KeySHA256 == keyDigest(key) {
			policies = append(policies, p)
		}
	}
	if len(policies) != 1 || policies[0].Pool == "" {
		return zero, nil, poolError("unclassified", 403)
	}
	for _, p := range *cfg.AccountPools {
		if p.ID == policies[0].Pool {
			return p, copyPolicies(policies), nil
		}
	}
	return zero, nil, poolError("unclassified", 403)
}

func (m *Manager) beginPoolOperation(ctx context.Context, key, model string, kind PoolOperationKind) (context.Context, *KeyPolicyOperation, error) {
	if m == nil {
		return ctx, nil, poolError("admission_required", 503)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ctx, nil, err
	}
	m.mu.RLock()
	opaqueTransport := m.rtProvider != nil
	m.mu.RUnlock()
	if _, injected := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); injected {
		opaqueTransport = true
	}
	if opaqueTransport {
		return ctx, nil, poolError("path_unavailable", 503)
	}
	if kind < PoolResponses || kind > PoolLiveCall || len(model) > 1024 || strings.TrimSpace(model) == "" || ex.DownstreamWebsocket(ctx) || ex.RequiredUpstreamWebsocket(ctx) {
		return ctx, nil, poolError("path_unavailable", 503)
	}
	m.keyPolicyMu.Lock()
	p, policies, err := m.poolPrincipalLocked(key)
	if err == nil && kind == PoolLiveCall && string(p.Class) != "human" {
		err = poolError("path_unavailable", 503)
	}
	if err == nil {
		for _, floor := range policies {
			if floor.AllowedModels != nil && !containsExact(*floor.AllowedModels, model) {
				err = policyError("api_key_model_forbidden", 403)
			}
		}
	}
	if err == nil && (p.MaxInFlight == nil || m.poolCounters[p.ID] >= *p.MaxInFlight) {
		err = poolError("capacity", 429)
	}
	if err != nil {
		m.keyPolicyMu.Unlock()
		return ctx, nil, err
	}
	if m.poolCounters == nil {
		m.poolCounters = make(map[string]int64)
	}
	m.poolCounters[p.ID]++
	m.keyPolicyMu.Unlock()
	// A single bridge has request cancellation authority until live transfer.
	// Values survive transfer, but no POST deadline/cancel survives it.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	op := &KeyPolicyOperation{manager: m, policies: policies, model: model, pool: &poolOperationState{pool: p, kind: kind, digest: keyDigest(key), cancel: cancel, done: make(chan struct{})}}
	lifetime = WithKeyPolicy(lifetime, op)
	op.pool.ctx = lifetime
	op.pool.stopBridge = context.AfterFunc(ctx, func() {
		op.mu.Lock()
		defer op.mu.Unlock()
		if !op.pool.live {
			op.pool.cancel()
		}
	})
	m.poolRuntime.mu.Lock()
	if m.poolRuntime.operations == nil {
		m.poolRuntime.operations = make(map[*KeyPolicyOperation]struct{})
	}
	m.poolRuntime.operations[op] = struct{}{}
	m.poolRuntime.mu.Unlock()
	return lifetime, op, nil
}

func (op *KeyPolicyOperation) transferPoolToLive(callID string) error {
	if !op.IsPoolOperation() || op.pool.kind != PoolLiveCall || !validPoolCallID(callID) {
		return poolError("admission_required", 503)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	p := op.pool
	if p.closing || p.finished || p.live || p.ctx.Err() != nil || p.selectedID == "" || p.bootstrapPending || !p.bootstrapComplete {
		return poolError("admission_required", 503)
	}
	// A fired cancellation callback must win even if it is waiting for this lock.
	if p.stopBridge != nil && !p.stopBridge() {
		return poolError("admission_required", 503)
	}
	p.live, p.callID = true, callID
	return nil
}

func (op *KeyPolicyOperation) finishPool(live bool) {
	if !op.IsPoolOperation() {
		return
	}
	op.mu.Lock()
	p := op.pool
	if p.live && !live {
		op.mu.Unlock()
		return
	}
	if p.closing {
		done := p.done
		op.mu.Unlock()
		<-done
		return
	}
	p.closing = true
	if p.stopBridge != nil {
		p.stopBridge()
	}
	p.cancel()
	op.mu.Unlock()
	p.work.Wait()
	op.manager.keyPolicyMu.Lock()
	op.manager.poolCounters[p.pool.ID]--
	op.manager.keyPolicyMu.Unlock()
	op.manager.poolRuntime.mu.Lock()
	delete(op.manager.poolRuntime.operations, op)
	op.manager.poolRuntime.mu.Unlock()
	op.mu.Lock()
	p.finished = true
	close(p.done)
	op.mu.Unlock()
}

func (op *KeyPolicyOperation) poolWork() (func(), error) {
	if !op.IsPoolOperation() {
		return func() {}, nil
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.pool.closing || op.pool.finished || op.pool.ctx.Err() != nil {
		return nil, poolError("admission_required", 503)
	}
	op.pool.work.Add(1)
	return op.pool.work.Done, nil
}

func (m *Manager) checkPoolAdmission(ctx context.Context) error {
	op := KeyPolicyFromContext(ctx)
	if !m.PoolMode() && !op.IsPoolOperation() {
		return nil
	}
	if op == nil || op.manager != m || !op.IsPoolOperation() {
		return poolError("admission_required", 503)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.pool.closing || op.pool.finished || op.pool.ctx.Err() != nil {
		return poolError("admission_required", 503)
	}
	return nil
}

// beginPoolExecution prevents reusing one slot for parallel business operations.
// Sequential credential/model retries remain in the ordinary conductor loops.
func (m *Manager) beginPoolExecution(ctx context.Context, providers []string, model string, count, stream bool, opts ex.Options) (context.Context, func(), error) {
	if err := m.checkPoolAdmission(ctx); err != nil {
		return ctx, nil, err
	}
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() {
		return ctx, func() {}, nil
	}
	if err := op.currentPoolFloor(); err != nil {
		return ctx, nil, err
	}
	requested, _ := opts.Metadata[ex.RequestedModelMetadataKey].(string)
	if model != op.model && requested != op.model {
		return ctx, nil, policyError("api_key_model_forbidden", 403)
	}
	if err := op.currentPoolModelFloor(model); err != nil {
		return ctx, nil, err
	}
	kind := op.pool.kind
	if count != (kind == PoolCountTokens) || (stream && (kind == PoolCompact || kind == PoolLiveCall)) || kind == PoolLiveCall || (kind == PoolCompact && opts.Alt != "responses/compact") || (kind != PoolCompact && opts.Alt != "") || opts.ProxyURL != "" || ex.DownstreamWebsocket(ctx) || ex.RequiredUpstreamWebsocket(ctx) {
		return ctx, nil, poolError("path_unavailable", 503)
	}
	want := "codex"
	if kind == PoolMessages || kind == PoolCountTokens {
		want = "claude"
	}
	if len(providers) == 0 {
		return ctx, nil, poolError("path_unavailable", 503)
	}
	for _, p := range providers {
		if p != want {
			return ctx, nil, poolError("path_unavailable", 503)
		}
	}
	op.mu.Lock()
	if op.pool.started || op.pool.closing || op.pool.finished {
		op.mu.Unlock()
		return ctx, nil, poolError("admission_required", 503)
	}
	op.pool.executing, op.pool.started = true, true
	op.pool.work.Add(1)
	op.mu.Unlock()
	executionCtx, cancelExecution := context.WithCancel(ctx)
	stopExecutionBridge := context.AfterFunc(op.pool.ctx, cancelExecution)
	done := func() {
		if !stream {
			stopExecutionBridge()
			cancelExecution()
		}
		op.mu.Lock()
		op.pool.executing = false
		op.mu.Unlock()
		op.pool.work.Done()
	}
	ctx, err := m.poolEligibilityContext(executionCtx, op)
	if err != nil {
		done()
		return ctx, nil, err
	}
	return ctx, done, nil
}

type poolEligibilityContextKey struct{}
type poolEligibility struct {
	proofs map[string]nativePoolProof
	op     *KeyPolicyOperation
}

func (op *KeyPolicyOperation) poolEligibilitySnapshot() *poolEligibility {
	r := &op.manager.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	proofs := make(map[string]nativePoolProof, len(r.proofs))
	for id, p := range r.proofs {
		if _, quarantined := r.quarantines[id]; quarantined {
			continue
		}
		if registration := r.registrations[p.identity.Provider]; registration.executor != nil && registration.epoch == p.executorEpoch && poolIdentityMember(op.pool.pool, p.identity) {
			proofs[id] = p
		}
	}
	return &poolEligibility{proofs: proofs, op: op}
}
func (e *poolEligibility) allows(a *Auth) bool {
	if e == nil || a == nil {
		return e == nil
	}
	if e.op.manager.poolCredentialQuarantined(a.ID) {
		return false
	}
	p, ok := e.proofs[a.ID]
	return ok && p.authEpoch == a.RegistrationEpoch && p.version == a.CredentialVersion && p.binding == poolCredentialBinding(a) && poolIdentityMember(e.op.pool.pool, p.identity)
}
func poolIdentityMember(p config.AccountPool, i NativePoolIdentity) bool {
	for _, a := range p.Accounts {
		if a.Provider == i.Provider && a.AccountID == i.AccountID && a.EntitlementID == i.EntitlementID {
			return true
		}
	}
	return false
}

func (m *Manager) poolEligibilityContext(ctx context.Context, op *KeyPolicyOperation) (context.Context, error) {
	proofs := make(map[string]nativePoolProof)
	for _, a := range m.snapshotAuths() {
		if !nativePoolCandidate(a) {
			continue
		}
		current, proof, err := m.acquirePoolProof(ctx, a)
		if errors.Is(err, errPoolCredentialQuarantined) {
			continue
		}
		if err != nil {
			return ctx, err
		}
		if err := m.checkPoolIdentityReservation(proof.identity); err != nil {
			return ctx, err
		}
		if poolIdentityMember(op.pool.pool, proof.identity) {
			proofs[current.ID] = proof
		}
	}
	if len(proofs) == 0 {
		return ctx, poolError("unavailable", 503)
	}
	return context.WithValue(ctx, poolEligibilityContextKey{}, &poolEligibility{proofs, op}), nil
}

// Revocation cancels owned work without releasing its capacity early.
func (m *Manager) cancelRevokedPoolOperations(cfg *config.Config) {
	r := &m.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	for op := range r.operations {
		found := false
		for _, key := range cfg.APIKeys {
			if keyDigest(key) == op.pool.digest {
				found = true
				break
			}
		}
		if !found {
			op.pool.cancel()
		}
	}
}

func (m *Manager) cancelPoolAuthOperationsLocked(id string) {
	for op := range m.poolRuntime.operations {
		if op == nil || op.pool == nil {
			continue
		}
		op.mu.Lock()
		_, used := op.pool.attemptedIDs[id]
		used = used || op.pool.selectedID == id
		op.mu.Unlock()
		if used {
			op.pool.cancel()
		}
	}
}

// Called with the ordinary manager mutation lock held; never waits on teardown.
func (m *Manager) cancelRetiredPoolAuthLocked(id string) {
	a := m.auths[id]
	r := &m.poolRuntime
	r.mu.Lock()
	defer r.mu.Unlock()
	proof, proven := r.proofs[id]
	if a == nil {
		delete(r.proofs, id)
		delete(r.retainedProofs, id)
		delete(r.quarantines, id)
		m.cancelPoolAuthOperationsLocked(id)
		return
	}
	if proven && !proofMatches(proof, a, r.registrations[a.Provider]) {
		// The configured owner is retained at proof publication, not replaced
		// by whichever (possibly unowned) active proof is being invalidated.
		delete(r.proofs, id)
		if a.Disabled || a.Status == StatusDisabled {
			m.cancelPoolAuthOperationsLocked(id)
		}
		return
	}
	if !a.Disabled && a.Status != StatusDisabled {
		return
	}
	delete(r.proofs, id)
	m.cancelPoolAuthOperationsLocked(id)
}

func (m *Manager) checkPoolIdentityReservation(i NativePoolIdentity) error {
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.poolRuntime.mu.Lock()
	defer m.poolRuntime.mu.Unlock()
	return m.poolIdentityReservationLocked(cfg, i)
}

type poolIdentityAtom struct{ provider, kind, id string }

func poolIdentityAtoms(i NativePoolIdentity) map[poolIdentityAtom]struct{} {
	atoms := map[poolIdentityAtom]struct{}{{i.Provider, "account", i.AccountID}: {}, {i.Provider, "entitlement", i.EntitlementID}: {}}
	for kind, id := range i.AccountAliases {
		atoms[poolIdentityAtom{i.Provider, "alias:" + kind, id}] = struct{}{}
	}
	return atoms
}
func poolIdentityOwner(cfg *config.Config, i NativePoolIdentity) (string, error) {
	if cfg == nil || cfg.AccountPools == nil {
		return "", poolError("identity_unverified", 503)
	}
	owner := ""
	for _, p := range *cfg.AccountPools {
		for _, a := range p.Accounts {
			if a.Provider == i.Provider && (a.AccountID == i.AccountID || a.EntitlementID == i.EntitlementID) {
				if owner != "" && owner != p.ID {
					return "", poolError("identity_unverified", 503)
				}
				owner = p.ID
			}
		}
	}
	return owner, nil
}

// Caller holds m.mu and poolRuntime.mu. Typed aliases are compared only with
// the same native claim kind; they are never alternate membership identifiers.
func (m *Manager) poolIdentityReservationLocked(cfg *config.Config, i NativePoolIdentity) error {
	owner, err := poolIdentityOwner(cfg, i)
	if err != nil {
		return err
	}
	atoms := poolIdentityAtoms(i)
	for id, p := range m.poolRuntime.proofs {
		r := m.poolRuntime.registrations[p.identity.Provider]
		if !proofMatches(p, m.auths[id], r) {
			continue
		}
		other, err := poolIdentityOwner(cfg, p.identity)
		if err != nil {
			return err
		}
		if owner == "" || other == "" || owner == other {
			continue
		}
		for atom := range poolIdentityAtoms(p.identity) {
			if _, overlap := atoms[atom]; overlap {
				return poolError("identity_unverified", 503)
			}
		}
	}
	return nil
}
