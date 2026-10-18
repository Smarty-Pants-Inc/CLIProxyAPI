package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"regexp"
	"sync"

	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const poolLiveBootstrapURL = "https://chatgpt.com/backend-api/codex/realtime/calls?intent=quicksilver&architecture=avas"

var poolLiveCallID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,256}$`)

func validPoolCallID(id string) bool { return poolLiveCallID.MatchString(id) }

func (m *Manager) selectPoolLiveAuth(ctx context.Context, pinned string) (*Auth, error) {
	if err := m.checkPoolAdmission(ctx); err != nil {
		return nil, err
	}
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() || op.pool.kind != PoolLiveCall || string(op.pool.pool.Class) != "human" {
		return nil, poolError("path_unavailable", 503)
	}
	if err := op.currentPoolFloor(); err != nil {
		return nil, err
	}
	done, err := op.poolWork()
	if err != nil {
		return nil, err
	}
	defer done()
	ctx, err = m.poolEligibilityContext(ctx, op)
	if err != nil {
		return nil, err
	}
	op.mu.Lock()
	selectedID, wasLive := op.pool.selectedID, op.pool.live
	op.mu.Unlock()
	if selectedID != "" {
		if pinned != "" && pinned != selectedID {
			return nil, poolError("live_scope_mismatch", 403)
		}
		pinned = selectedID
	}
	if wasLive && pinned == "" {
		return nil, poolError("live_scope_mismatch", 403)
	}
	opts := ex.Options{Metadata: make(map[string]any)}
	if pinned != "" {
		opts.Metadata[ex.PinnedAuthMetadataKey] = pinned
	}
	// Live models intentionally do not live in the ordinary generation registry.
	// Empty selection model reuses native OAuth strategy; op.model is separately
	// validated at admission, publication and the final nested live payload fence.
	selected, _, err := m.pickNextLegacy(withRequiredAuthKind(ctx, AuthKindOAuth), "codex", "", opts, nil)
	if err != nil {
		return nil, poolError("unavailable", 503)
	}
	selected, proof, err := m.acquirePoolProof(ctx, selected)
	if err != nil {
		return nil, err
	}
	if m.poolCredentialQuarantined(selected.ID) {
		return nil, poolError("identity_unverified", 503)
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.pool.closing || op.pool.finished {
		return nil, poolError("admission_required", 503)
	}
	if op.pool.selectedID != "" && (selected.ID != op.pool.selectedID || !samePoolIdentity(op.pool.identity, proof.identity)) {
		return nil, poolError("identity_unverified", 503)
	}
	op.pool.selectedID, op.pool.identity = selected.ID, clonePoolIdentity(proof.identity)
	return selected, nil
}
func samePoolIdentity(a, b NativePoolIdentity) bool {
	return a.Provider == b.Provider && a.AccountID == b.AccountID && a.EntitlementID == b.EntitlementID
}

func (m *Manager) newPoolLiveRequest(ctx context.Context, selected *Auth, callID string, body []byte, headers http.Header) (*http.Request, error) {
	if err := m.checkPoolAdmission(ctx); err != nil {
		return nil, err
	}
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() || op.pool.kind != PoolLiveCall || selected == nil {
		return nil, poolError("path_unavailable", 503)
	}
	op.mu.Lock()
	pinned, live, storedCall := op.pool.selectedID, op.pool.live, op.pool.callID
	identity := clonePoolIdentity(op.pool.identity)
	op.mu.Unlock()
	if pinned == "" || selected.ID != pinned {
		return nil, poolError("identity_unverified", 503)
	}
	if m.poolCredentialQuarantined(pinned) {
		return nil, poolError("identity_unverified", 503)
	}
	method, target := http.MethodPost, poolLiveBootstrapURL
	if callID != "" {
		if !live || !validPoolCallID(callID) || callID != storedCall || len(body) != 0 {
			return nil, poolError("live_scope_mismatch", 403)
		}
		method, target = http.MethodGet, "https://api.openai.com/v1/live/"+callID
	} else if live {
		return nil, poolError("path_unavailable", 503)
	}
	ctx, current, err := m.poolAttemptContext(ctx, selected, op.model)
	if err != nil {
		return nil, err
	}
	if !samePoolIdentity(identity, ctx.Value(poolAttemptContextKey{}).(*nativePoolAttempt).proof.identity) {
		return nil, poolError("identity_unverified", 503)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header = headers.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	request.Header.Set("Authorization", "Bearer "+current.MetadataString("access_token"))
	request.Header.Set("Chatgpt-Account-Id", current.MetadataString("account_id"))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	// Built-in preparation runs before freezing the exact request. No payload
	// rules run here: the live finalizer already owns the final semantic barrier.
	executor := m.executorFor("codex")
	preparer, ok := executor.(RequestPreparer)
	if !ok || executor != ctx.Value(poolAttemptContextKey{}).(*nativePoolAttempt).executor {
		return nil, poolError("path_unavailable", 503)
	}
	if err := preparer.PrepareRequest(request, current); err != nil {
		return nil, err
	}
	attempt := ctx.Value(poolAttemptContextKey{}).(*nativePoolAttempt)
	attempt.liveRequest, attempt.liveDigest = request, requestPoolDigest(request, body)
	request.GetBody = nil
	return request, nil
}

func (m *Manager) sendPoolLiveRequest(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, poolError("path_unavailable", 503)
	}
	if err := m.checkPoolAdmission(req.Context()); err != nil {
		return nil, err
	}
	attempt, _ := req.Context().Value(poolAttemptContextKey{}).(*nativePoolAttempt)
	if attempt == nil || attempt.op.manager != m || attempt.liveRequest != req || req.Method != http.MethodPost {
		return nil, poolError("path_unavailable", 503)
	}
	var body []byte
	if req.Body != nil {
		var errRead error
		body, errRead = io.ReadAll(req.Body)
		errClose := req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		if errRead != nil || errClose != nil {
			return nil, poolError("path_unavailable", 503)
		}
	}
	if requestPoolDigest(req, body) != attempt.liveDigest {
		return nil, poolError("path_unavailable", 503)
	}
	doneWork, err := attempt.op.poolWork()
	if err != nil {
		return nil, err
	}
	op := attempt.op
	op.mu.Lock()
	if op.pool.started || op.pool.closing || op.pool.finished || op.pool.live || op.pool.ctx.Err() != nil {
		op.mu.Unlock()
		doneWork()
		return nil, poolError("admission_required", 503)
	}
	op.pool.started, op.pool.bootstrapPending = true, true
	op.mu.Unlock()
	done := func(errClose error, success bool) {
		op.mu.Lock()
		op.pool.bootstrapPending = false
		op.pool.bootstrapComplete = success && errClose == nil
		op.mu.Unlock()
		doneWork()
	}
	executor := m.executorFor("codex")
	if executor == nil || executor != attempt.executor {
		done(nil, false)
		return nil, poolError("path_unavailable", 503)
	}
	resp, err := executor.HttpRequest(req.Context(), attempt.auth, req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		done(nil, false)
		return nil, err
	}
	if resp == nil || resp.Body == nil {
		done(nil, false)
		return nil, poolError("path_unavailable", 503)
	}
	// The live handler closes bootstrap before transfer. Ownership survives until
	// that real body cleanup completes, even on canceled/error bootstrap paths.
	bodyOwner := &poolLiveBody{ReadCloser: resp.Body, done: func(errClose error) { done(errClose, resp.StatusCode >= 200 && resp.StatusCode < 300) }}
	context.AfterFunc(req.Context(), func() { _ = bodyOwner.Close() })
	resp.Body = bodyOwner
	return resp, nil
}

type poolLiveBody struct {
	io.ReadCloser
	done func(error)
	once sync.Once
	err  error
}

func (b *poolLiveBody) Close() error {
	b.once.Do(func() { b.err = b.ReadCloser.Close(); b.done(b.err) })
	return b.err
}
