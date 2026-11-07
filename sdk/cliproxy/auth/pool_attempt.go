package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolAttemptContextKey struct{}
type nativePoolAttempt struct {
	mu          sync.Mutex
	op          *KeyPolicyOperation
	auth        *Auth
	proof       nativePoolProof
	executor    ProviderExecutor
	model       string
	sent        bool
	liveRequest *http.Request
	liveDigest  [32]byte
}

func (m *Manager) poolAttemptContext(ctx context.Context, a *Auth, model string) (context.Context, *Auth, error) {
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() {
		return ctx, a, nil
	}
	if err := m.checkPoolAdmission(ctx); err != nil {
		return ctx, nil, wrapRequestStopError(err)
	}
	if err := op.currentPoolFloor(); err != nil {
		return ctx, nil, wrapRequestStopError(err)
	}
	current, proof, err := m.acquirePoolProof(ctx, a)
	if err != nil {
		return ctx, nil, wrapRequestStopError(err)
	}
	if m.poolCredentialQuarantined(current.ID) {
		return ctx, nil, wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if !poolIdentityMember(op.pool.pool, proof.identity) {
		return ctx, nil, wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if err := m.checkPoolIdentityReservation(proof.identity); err != nil {
		return ctx, nil, wrapRequestStopError(err)
	}
	parsed := thinking.ParseSuffix(model)
	if parsed.ModelName != "" {
		model = parsed.ModelName
	}
	op.mu.Lock()
	if op.pool.attemptedIDs == nil {
		op.pool.attemptedIDs = make(map[string]struct{})
	}
	op.pool.attemptedIDs[current.ID] = struct{}{}
	op.mu.Unlock()
	m.poolRuntime.mu.Lock()
	registration := m.poolRuntime.registrations[current.Provider]
	m.poolRuntime.mu.Unlock()
	if registration.executor == nil || registration.epoch != proof.executorEpoch {
		return ctx, nil, wrapRequestStopError(poolError("identity_unverified", 503))
	}
	attempt := &nativePoolAttempt{op: op, auth: current.Clone(), proof: proof, executor: registration.executor, model: model}
	return context.WithValue(ctx, poolAttemptContextKey{}, attempt), current, nil
}

func (m *Manager) executeNativePoolAware(ctx context.Context, executor ProviderExecutor, a *Auth, req ex.Request, opts ex.Options, count bool) (ex.Response, error) {
	ctx, a, err := m.poolAttemptContext(ctx, a, req.Model)
	if err != nil {
		return ex.Response{}, err
	}
	if attempt, _ := ctx.Value(poolAttemptContextKey{}).(*nativePoolAttempt); attempt != nil && attempt.executor != executor {
		return ex.Response{}, wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if count {
		return executor.CountTokens(ctx, a, req, opts)
	}
	return executor.Execute(ctx, a, req, opts)
}

func (m *Manager) streamNativePoolAware(ctx context.Context, cancel context.CancelFunc, executor ProviderExecutor, a *Auth, req ex.Request, opts ex.Options) (*ex.StreamResult, error) {
	ctx, a, err := m.poolAttemptContext(ctx, a, req.Model)
	if err != nil {
		return nil, err
	}
	if attempt, _ := ctx.Value(poolAttemptContextKey{}).(*nativePoolAttempt); attempt != nil && attempt.executor != executor {
		return nil, wrapRequestStopError(poolError("identity_unverified", 503))
	}
	result, err := executor.ExecuteStream(ctx, a, req, opts)
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() || result == nil || result.Chunks == nil {
		return result, err
	}
	owned, errOwned := ownPoolSource(ctx, op, result, cancel)
	if errOwned != nil {
		return nil, errOwned
	}
	return owned, err
}

// Exactly one receiver owns the native source, including all abandoned/bootstrap
// error paths. Its terminal barrier follows source closure (and native body.Close).
// Cancel acknowledgments precede producer cancellation; draining ignores ctx.Done.
func ownPoolSource(ctx context.Context, op *KeyPolicyOperation, source *ex.StreamResult, cancel context.CancelFunc) (*ex.StreamResult, error) {
	done, err := op.poolWork()
	if err != nil {
		if source.Complete != nil {
			source.Complete(false)
		}
		cancel()
		for range source.Chunks {
		}
		return nil, err
	}
	out := make(chan ex.StreamChunk)
	terminal := make(chan struct{})
	var rejectOnce sync.Once
	reject := func() {
		rejectOnce.Do(func() {
			if source.Complete != nil {
				source.Complete(false)
			}
			cancel()
		})
	}
	go func() {
		defer done()
		defer close(terminal)
		defer close(out)
		forward := true
		for {
			if !forward {
				for range source.Chunks {
				}
				return
			}
			select {
			case <-ctx.Done():
				reject()
				forward = false
			case chunk, ok := <-source.Chunks:
				if !ok {
					return
				}
				select {
				case out <- chunk:
				case <-ctx.Done():
					reject()
					forward = false
				}
			}
		}
	}()
	// Conductor cancellation is synchronous terminal ownership, not an ACK.
	complete := func(accepted bool) {
		if accepted {
			if source.Complete != nil {
				source.Complete(true)
			}
		} else {
			reject()
			<-terminal
		}
	}
	return &ex.StreamResult{Headers: source.Headers, Chunks: out, Complete: complete}, nil
}

// CheckNativePoolSend is the final factory fence beneath native header mutators.
// It never changes business payload semantics. Body replacement is serialization
// framing only, and GetBody is removed so transport cannot replay a business send.
func CheckNativePoolSend(req *http.Request) error {
	if req == nil {
		return poolError("path_unavailable", 503)
	}
	op := KeyPolicyFromContext(req.Context())
	if !op.IsPoolOperation() {
		return nil
	}
	attempt, _ := req.Context().Value(poolAttemptContextKey{}).(*nativePoolAttempt)
	if attempt == nil || attempt.op != op {
		return wrapRequestStopError(poolError("admission_required", 503))
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.sent {
		return wrapRequestStopError(poolError("path_unavailable", 503))
	}
	if err := op.manager.checkPoolAdmission(req.Context()); err != nil {
		return wrapRequestStopError(err)
	}
	if err := op.currentPoolFloor(); err != nil {
		return wrapRequestStopError(err)
	}
	if err := op.currentPoolModelFloor(attempt.model); err != nil {
		return wrapRequestStopError(err)
	}
	a := attempt.auth
	m := op.manager
	m.mu.RLock()
	defer m.mu.RUnlock()
	current := m.auths[a.ID]
	rt := &m.poolRuntime
	rt.mu.Lock()
	defer rt.mu.Unlock()
	registration := rt.registrations[a.Provider]
	// New/replaced candidates cannot appear between the acquisition snapshot and
	// send as an unobserved alternate account/entitlement boundary.
	for id, candidate := range m.auths {
		if !nativePoolCandidate(candidate) {
			continue
		}
		if _, quarantined := rt.quarantines[id]; quarantined {
			continue
		}
		p, exists := rt.proofs[id]
		if !exists || !proofMatches(p, candidate, rt.registrations[candidate.Provider]) {
			return wrapRequestStopError(poolError("identity_unverified", 503))
		}
	}
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	if err := m.poolIdentityReservationLocked(cfg, attempt.proof.identity); err != nil {
		return wrapRequestStopError(err)
	}
	proof, ok := rt.proofs[a.ID]
	if !ok || registration.executor != attempt.executor || current == nil || !nativePoolCandidate(current) || !proofMatches(proof, current, registration) || proof.binding != attempt.proof.binding || proof.authEpoch != attempt.proof.authEpoch || proof.version != attempt.proof.version || !poolIdentityMember(op.pool.pool, proof.identity) {
		return wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if blocked, _, _ := isAuthBlockedForModel(current, attempt.model, time.Now()); blocked {
		return wrapRequestStopError(poolError("unavailable", 503))
	}
	if op.pool.kind != PoolLiveCall && !registry.GetGlobalRegistry().ClientSupportsModel(a.ID, attempt.model) {
		return wrapRequestStopError(poolError("unavailable", 503))
	}
	op.mu.Lock()
	callID := op.pool.callID
	op.mu.Unlock()
	if !poolTargetAllowed(req, op.pool.kind, a.Provider, callID) {
		return wrapRequestStopError(poolError("path_unavailable", 503))
	}
	if !exactPoolHeader(req.Header, "Authorization", "Bearer "+a.MetadataString("access_token")) || !exactPoolHeader(req.Header, "X-Api-Key", "") {
		return wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if a.Provider == "codex" && (!exactPoolHeader(req.Header, "Chatgpt-Account-Id", proof.identity.EntitlementID) || a.MetadataString("account_id") != proof.identity.EntitlementID) {
		return wrapRequestStopError(poolError("identity_unverified", 503))
	}
	if a.Provider == "claude" && (!exactPoolHeader(req.Header, "Chatgpt-Account-Id", "") || a.MetadataString("account_uuid") != proof.identity.AccountID || a.MetadataString("organization_uuid") != proof.identity.EntitlementID) {
		return wrapRequestStopError(poolError("identity_unverified", 503))
	}
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		errClose := req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil || errClose != nil {
			return wrapRequestStopError(poolError("path_unavailable", 503))
		}
	}
	for _, header := range []string{"Openai-Organization", "Openai-Project", "Anthropic-Organization-Id", "X-Organization-Id"} {
		if !exactPoolHeader(req.Header, header, "") {
			return wrapRequestStopError(poolError("identity_unverified", 503))
		}
	}
	if req.Method == http.MethodPost {
		model, err := ex.PolicyModel(body)
		if op.pool.kind == PoolLiveCall {
			var v struct {
				Session struct {
					Model string `json:"model"`
				} `json:"session"`
				SDP string `json:"sdp"`
			}
			if _, errUnique := ex.PolicyModel(append(append([]byte(`{"model":"_","value":`), body...), '}')); errUnique != nil {
				return wrapRequestStopError(poolError("path_unavailable", 503))
			}
			err = json.Unmarshal(body, &v)
			model = v.Session.Model
			if v.SDP == "" {
				return wrapRequestStopError(poolError("path_unavailable", 503))
			}
		}
		if err != nil || model != attempt.model {
			return wrapRequestStopError(policyError("api_key_model_forbidden", 403))
		}
		if a.Provider == "claude" && !claudePoolBodyIdentity(body, proof.identity) {
			return wrapRequestStopError(poolError("identity_unverified", 503))
		}
	}
	if attempt.liveRequest != nil && requestPoolDigest(req, body) != attempt.liveDigest {
		return wrapRequestStopError(poolError("path_unavailable", 503))
	}
	req.GetBody = nil
	attempt.sent = true
	return nil
}

func claudePoolBodyIdentity(body []byte, identity NativePoolIdentity) bool {
	var fields struct {
		Metadata struct {
			UserID json.RawMessage `json:"user_id"`
		} `json:"metadata"`
	}
	if json.Unmarshal(body, &fields) != nil {
		return false
	}
	if len(fields.Metadata.UserID) == 0 {
		return true
	} // count-tokens intentionally omits metadata
	var text string
	if json.Unmarshal(fields.Metadata.UserID, &text) != nil {
		return false
	}
	if _, err := ex.PolicyModel(append(append([]byte(`{"model":"_","value":`), []byte(text)...), '}')); err != nil {
		return false
	}
	var account struct {
		Account      string `json:"account_uuid"`
		Organization string `json:"organization_uuid"`
	}
	return json.Unmarshal([]byte(text), &account) == nil && account.Account == identity.AccountID && (account.Organization == "" || account.Organization == identity.EntitlementID)
}

func exactPoolHeader(h http.Header, name, want string) bool {
	var values []string
	for key, vv := range h {
		if strings.EqualFold(key, name) {
			values = append(values, vv...)
		}
	}
	if want == "" {
		return len(values) == 0
	}
	return len(values) == 1 && values[0] == want
}
func poolTargetAllowed(r *http.Request, kind PoolOperationKind, provider, callID string) bool {
	u := r.URL
	if u == nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || (r.Host != "" && r.Host != u.Host) || !exactPoolHeader(r.Header, "Host", "") {
		return false
	}
	if kind == PoolLiveCall && provider == "codex" {
		if r.Method == http.MethodPost {
			return u.String() == poolLiveBootstrapURL && callID == ""
		}
		return r.Method == http.MethodGet && u.Host == "api.openai.com" && u.RawQuery == "" && callID != "" && u.Path == "/v1/live/"+callID
	}
	if r.Method != http.MethodPost {
		return false
	}
	if provider == "codex" && u.Host == "chatgpt.com" && u.RawQuery == "" {
		return (kind == PoolResponses && u.Path == "/backend-api/codex/responses") || (kind == PoolCompact && u.Path == "/backend-api/codex/responses/compact")
	}
	if provider == "claude" && u.Host == "api.anthropic.com" && u.RawQuery == "beta=true" {
		return (kind == PoolMessages && u.Path == "/v1/messages") || (kind == PoolCountTokens && u.Path == "/v1/messages/count_tokens")
	}
	return false
}
func requestPoolDigest(req *http.Request, body []byte) [32]byte {
	// An absent body and an empty transport body carry identical bytes. In
	// particular, net/http represents a minted GET body as http.NoBody.
	if len(body) == 0 {
		body = nil
	}
	b, _ := json.Marshal(struct {
		Method, URL, Host string
		Headers           http.Header
		Body              []byte
	}{req.Method, req.URL.String(), req.Host, req.Header, body})
	return sha256.Sum256(b)
}
func (op *KeyPolicyOperation) currentPoolFloor() error { return op.currentPoolModelFloor(op.model) }
func (op *KeyPolicyOperation) currentPoolModelFloor(model string) error {
	m := op.manager
	m.keyPolicyMu.Lock()
	defer m.keyPolicyMu.Unlock()
	cfg, _ := m.runtimeConfig.Load().(*config.Config)
	if cfg == nil || cfg.AccountPools == nil || m.poolInvalid.Load() || cfg.Home.Enabled || cfg.Plugins.Enabled {
		return poolError("path_unavailable", 503)
	}
	configured := false
	for _, key := range cfg.APIKeys {
		if keyDigest(key) == op.pool.digest {
			configured = true
		}
	}
	if !configured {
		return poolError("unclassified", 403)
	}
	found := false
	for _, p := range append(copyPolicies(op.policies), cfg.APIKeyPolicies...) {
		if p.KeySHA256 != op.pool.digest {
			continue
		}
		if p.Pool != op.pool.pool.ID {
			return poolError("unclassified", 403)
		}
		found = true
		if p.AllowedModels != nil && !containsExact(*p.AllowedModels, model) {
			return policyError("api_key_model_forbidden", 403)
		}
	}
	if !found {
		return poolError("unclassified", 403)
	}
	return nil
}
