package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const runtimePoolModel = "pool-runtime-model"
const runtimePoolPayload = `{"model":"pool-runtime-model","input":"test"}`

func runtimePoolManager(t *testing.T, cap int64, selector Selector) *Manager {
	t.Helper()
	raw := fmt.Sprintf(`ws-auth: true
codex:
  live-media-relay:
    enabled: true
access:
  api-keys: ["pool-a", "pool-b", "pool-human"]
  account-pools:
    - id: agents
      org: test
      class: agent
      max-in-flight: %d
      accounts:
        - {provider: codex, account-id: user-a, entitlement-id: entitlement-a}
        - {provider: codex, account-id: user-b, entitlement-id: entitlement-b}
        - {provider: claude, account-id: "11111111-1111-4111-8111-111111111111", entitlement-id: "22222222-2222-4222-8222-222222222222"}
    - id: humans
      org: test
      class: human
      max-in-flight: 1
      accounts:
        - {provider: codex, account-id: user-human, entitlement-id: entitlement-human}
  api-key-policies:
    - {key-sha256: "%x", pool: agents}
    - {key-sha256: "%x", pool: agents}
    - {key-sha256: "%x", pool: humans}
`, cap, sha256.Sum256([]byte("pool-a")), sha256.Sum256([]byte("pool-b")), sha256.Sum256([]byte("pool-human")))
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, selector, nil)
	m.SetConfig(cfg)
	if !m.PoolMode() {
		t.Fatal("pool snapshot silently became legacy")
	}
	return m
}
func requirePoolStatus(t *testing.T, err error, status int) {
	t.Helper()
	var typed interface{ StatusCode() int }
	if !errors.As(err, &typed) || typed.StatusCode() != status {
		t.Fatalf("err=%v; want status %d", err, status)
	}
}
func admitRuntimePool(t *testing.T, m *Manager, key string, kind PoolOperationKind) (context.Context, *KeyPolicyOperation) {
	t.Helper()
	ctx, op, err := m.BeginPoolOperation(context.Background(), key, runtimePoolModel, kind)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Finish)
	return ctx, op
}

func TestPoolAggregateCapacityAndNativePrincipal(t *testing.T) {
	m := runtimePoolManager(t, 2, nil)
	_, a := admitRuntimePool(t, m, "pool-a", PoolResponses)
	_, b := admitRuntimePool(t, m, "pool-b", PoolMessages)
	_, _, err := m.BeginPoolOperation(context.Background(), "pool-a", runtimePoolModel, PoolCountTokens)
	requirePoolStatus(t, err, 429)
	_, _, err = m.BeginPoolOperation(context.Background(), fmt.Sprintf("%x", sha256.Sum256([]byte("pool-a"))), runtimePoolModel, PoolResponses)
	requirePoolStatus(t, err, 403)
	_, human, err := m.BeginPoolOperation(context.Background(), "pool-human", runtimePoolModel, PoolMessages)
	if err != nil {
		t.Fatalf("different pool borrowed aggregate counter: %v", err)
	}
	human.Finish()
	a.Finish()
	a.Finish()
	_, c := admitRuntimePool(t, m, "pool-b", PoolCountTokens)
	c.Finish()
	b.Finish()
	zero := runtimePoolManager(t, 0, nil)
	_, _, err = zero.BeginPoolOperation(context.Background(), "pool-a", runtimePoolModel, PoolResponses)
	requirePoolStatus(t, err, 429)
}

func TestPoolInvalidInitialSDKSnapshotCannotBecomeOff(t *testing.T) {
	m := NewManager(nil, nil, nil)
	m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"orphan"}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("orphan"))), Pool: "missing-topology"}}}, WebsocketAuth: true})
	if !m.PoolMode() {
		t.Fatal("invalid initial pooled SDK policy silently became OFF")
	}
	_, err := m.Execute(context.Background(), []string{"codex"}, ex.Request{Model: runtimePoolModel}, ex.Options{})
	requirePoolStatus(t, err, 503)
	m.SetConfig(&config.Config{})
	if !m.PoolMode() {
		t.Fatal("invalid initial pool snapshot was silently cleared by an OFF snapshot")
	}
}

func TestPoolWrongManagerFinishedAndForgedContext(t *testing.T) {
	m := runtimePoolManager(t, 1, nil)
	ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
	other := runtimePoolManager(t, 1, nil)
	_, err := other.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
	requirePoolStatus(t, err, 503)
	fake := WithKeyPolicy(context.Background(), &KeyPolicyOperation{manager: m})
	_, err = m.Execute(fake, []string{"codex"}, ex.Request{Model: runtimePoolModel}, ex.Options{})
	requirePoolStatus(t, err, 503)
	op.Finish()
	_, err = m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel}, ex.Options{})
	requirePoolStatus(t, err, 503)
	_, _, err = m.BeginKeyPolicy(context.Background(), m.KeyPolicies("pool-a"), runtimePoolModel)
	requirePoolStatus(t, err, 503)
}

type runtimePoolExecutor struct {
	mu           sync.Mutex
	provider     string
	identities   map[string]NativePoolIdentity
	acquisitions int
	sends        []string
	fail         string
	stream       func(context.Context, *Auth) (*ex.StreamResult, error)
}

func (e *runtimePoolExecutor) Identifier() string { return e.provider }
func (e *runtimePoolExecutor) AcquirePoolIdentity(_ context.Context, a *Auth) (*Auth, NativePoolIdentity, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.acquisitions++
	i, ok := e.identities[a.ID]
	if !ok {
		return nil, NativePoolIdentity{}, errors.New("fixture identity missing")
	}
	a = a.Clone()
	if e.provider == "codex" {
		a.SetMetadata("account_id", i.EntitlementID)
	} else {
		a.SetMetadata("account_uuid", i.AccountID)
		a.SetMetadata("organization_uuid", i.EntitlementID)
	}
	return a, i, nil
}
func (e *runtimePoolExecutor) PrepareRequest(r *http.Request, a *Auth) error {
	r.Header.Set("Authorization", "Bearer "+a.MetadataString("access_token"))
	return nil
}
func (e *runtimePoolExecutor) send(ctx context.Context, a *Auth, payload []byte) (*http.Request, error) {
	op := KeyPolicyFromContext(ctx)
	target := "https://chatgpt.com/backend-api/codex/responses"
	if op.pool.kind == PoolCompact {
		target += "/compact"
	}
	if e.provider == "claude" {
		target = "https://api.anthropic.com/v1/messages"
		if op.pool.kind == PoolCountTokens {
			target += "/count_tokens"
		}
		target += "?beta=true"
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	e.PrepareRequest(r, a)
	if e.provider == "codex" {
		r.Header.Set("Chatgpt-Account-Id", a.MetadataString("account_id"))
	}
	if err = CheckNativePoolSend(r); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.sends = append(e.sends, a.ID)
	e.mu.Unlock()
	return r, nil
}
func (e *runtimePoolExecutor) Execute(ctx context.Context, a *Auth, r ex.Request, _ ex.Options) (ex.Response, error) {
	if _, err := e.send(ctx, a, r.Payload); err != nil {
		return ex.Response{}, err
	}
	if a.ID == e.fail {
		return ex.Response{}, &Error{HTTPStatus: 503, Message: "fixture upstream unavailable"}
	}
	return ex.Response{Payload: []byte(`{"output":[]}`)}, nil
}
func (e *runtimePoolExecutor) CountTokens(ctx context.Context, a *Auth, r ex.Request, o ex.Options) (ex.Response, error) {
	return e.Execute(ctx, a, r, o)
}
func (e *runtimePoolExecutor) ExecuteStream(ctx context.Context, a *Auth, r ex.Request, _ ex.Options) (*ex.StreamResult, error) {
	if _, err := e.send(ctx, a, r.Payload); err != nil {
		return nil, err
	}
	return e.stream(ctx, a)
}
func (e *runtimePoolExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, errors.New("generic refresh must not run")
}
func (e *runtimePoolExecutor) HttpRequest(ctx context.Context, a *Auth, r *http.Request) (*http.Response, error) {
	if err := CheckNativePoolSend(r); err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.sends = append(e.sends, a.ID)
	e.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
}
func registerRuntimePoolAuth(t *testing.T, m *Manager, e *runtimePoolExecutor, suffix, user, entitlement string) *Auth {
	t.Helper()
	id := t.Name() + suffix
	if e.identities == nil {
		e.identities = make(map[string]NativePoolIdentity)
	}
	e.identities[id] = NativePoolIdentity{Provider: e.provider, AccountID: user, EntitlementID: entitlement}
	a, err := m.Register(context.Background(), &Auth{ID: id, Provider: e.provider, Status: StatusActive, Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": "fake-access-" + suffix, "refresh_token": "fake-refresh-" + suffix, "verified": true, "account_id": "forged-file-value"}})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, e.provider, []*registry.ModelInfo{{ID: runtimePoolModel}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	return a
}

func TestPoolNativeRegistrationAndSamePoolRetry(t *testing.T) {
	for _, selector := range []Selector{&RoundRobinSelector{}, &FillFirstSelector{}} {
		t.Run(fmt.Sprintf("%T", selector), func(t *testing.T) {
			m := runtimePoolManager(t, 1, selector)
			e := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
			registerRuntimePoolAuth(t, m, e, "-b", "user-b", "entitlement-b")
			m.RegisterExecutor(e)
			ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
			_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
			requirePoolStatus(t, err, 503)
			op.Finish()
			if e.acquisitions != 0 || len(e.sends) != 0 {
				t.Fatalf("ordinary registration was trusted: %+v", e)
			}
			if err = m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			e.fail = a.ID
			ctx, op = admitRuntimePool(t, m, "pool-a", PoolResponses)
			_, err = m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
			if err != nil {
				t.Fatal(err)
			}
			op.Finish()
			if len(e.sends) != 2 || e.sends[0] != a.ID || e.sends[1] == a.ID {
				t.Fatalf("same-pool retry path=%v", e.sends)
			}
			// A later ordinary registration invalidates proofs even for the same instance.
			m.RegisterExecutor(e)
			ctx, op = admitRuntimePool(t, m, "pool-b", PoolResponses)
			_, err = m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
			requirePoolStatus(t, err, 503)
			op.Finish()
		})
	}
}

func TestPoolForeignPinAndTypedAliasCollision(t *testing.T) {
	m := runtimePoolManager(t, 2, nil)
	e := &runtimePoolExecutor{provider: "codex"}
	a := registerRuntimePoolAuth(t, m, e, "-agent", "user-a", "entitlement-a")
	h := registerRuntimePoolAuth(t, m, e, "-human", "user-human", "entitlement-human")
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	ctx, op := admitRuntimePool(t, m, "pool-a", PoolCompact)
	_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{Alt: "responses/compact", Metadata: map[string]any{ex.PinnedAuthMetadataKey: h.ID}})
	if err == nil || len(e.sends) != 0 {
		t.Fatalf("foreign compact pin escaped pool: %v sends=%v", err, e.sends)
	}
	op.Finish()
	// Identical native alias atoms reveal cross-pool identity overlap despite
	// different file IDs, primary IDs, and copied/forged metadata hints.
	e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-a", EntitlementID: "entitlement-a", AccountAliases: map[string]string{"sub": "same-native-sub"}}
	e.identities[h.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human", AccountAliases: map[string]string{"sub": "same-native-sub"}}
	if err = m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	ctx, op = admitRuntimePool(t, m, "pool-a", PoolResponses)
	_, err = m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
	requirePoolStatus(t, err, 503)
	if len(e.sends) != 0 {
		t.Fatalf("ambiguous native aliases sent: %v", e.sends)
	}
	op.Finish()
}

func TestPoolCanceledAndAbandonedSourceKeepsCapacity(t *testing.T) {
	for _, consume := range []bool{false, true} {
		t.Run(fmt.Sprint(consume), func(t *testing.T) {
			m := runtimePoolManager(t, 1, nil)
			e := &runtimePoolExecutor{provider: "codex"}
			registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
			cleanupStarted, cleanupAllowed := make(chan struct{}), make(chan struct{})
			e.stream = func(ctx context.Context, _ *Auth) (*ex.StreamResult, error) {
				out := make(chan ex.StreamChunk)
				go func() {
					defer close(out)
					select {
					case out <- ex.StreamChunk{Payload: []byte(`data: {"type":"response.output_text.delta","delta":"hello"}`)}:
					case <-ctx.Done():
					}
					<-ctx.Done()
					close(cleanupStarted)
					<-cleanupAllowed
				}()
				return &ex.StreamResult{Chunks: out}, nil // no Complete callback
			}
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
			var allowOnce sync.Once
			allowCleanup := func() { allowOnce.Do(func() { close(cleanupAllowed) }) }
			defer allowCleanup()
			result, err := m.ExecuteStream(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{Stream: true})
			if err != nil {
				t.Fatal(err)
			}
			if consume {
				if _, ok := <-result.Chunks; !ok {
					t.Fatal("positive payload missing")
				}
			}
			finished := make(chan struct{})
			go func() { op.Finish(); close(finished) }()
			<-cleanupStarted
			_, _, err = m.BeginPoolOperation(context.Background(), "pool-b", runtimePoolModel, PoolResponses)
			requirePoolStatus(t, err, 429)
			select {
			case <-finished:
				t.Fatal("capacity released before actual source/body cleanup")
			default:
			}
			allowCleanup()
			for range result.Chunks {
			}
			<-finished
			_, next := admitRuntimePool(t, m, "pool-b", PoolCountTokens)
			next.Finish()
		})
	}
}

func TestPoolSchedulerLegacyAndRetryEligibilityParity(t *testing.T) {
	m := runtimePoolManager(t, 1, nil)
	e := &runtimePoolExecutor{provider: "codex"}
	a := registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
	h := registerRuntimePoolAuth(t, m, e, "-human", "user-human", "entitlement-human")
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
	defer op.Finish()
	ctx, err := m.poolEligibilityContext(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []bool{false, true} {
		var selected *Auth
		opts := ex.Options{Metadata: map[string]any{}}
		if legacy {
			selected, _, err = m.pickNextLegacy(ctx, "codex", runtimePoolModel, opts, nil)
		} else {
			selected, _, err = m.pickNext(ctx, "codex", runtimePoolModel, opts, nil)
		}
		if err != nil || selected == nil || selected.ID != a.ID {
			t.Fatalf("legacy=%v selected=%v err=%v", legacy, selected, err)
		}
	}
	eligibility := authSelectionEligibilityForRequest(ctx, ex.Options{})
	if m.retryAllowed(0, []string{"codex"}, runtimePoolModel, eligibility, h.ID, 2) {
		t.Fatal("retry scan admitted a human pin")
	}
	if !m.retryAllowed(0, []string{"codex"}, runtimePoolModel, eligibility, a.ID, 2) {
		t.Fatal("same-pool retry scan was disabled")
	}
}

func TestPoolSignerAndConversationNamespaces(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	defer selector.Stop()
	m := runtimePoolManager(t, 1, selector)
	e := &runtimePoolExecutor{provider: "codex"}
	registerRuntimePoolAuth(t, m, e, "-agent", "user-a", "entitlement-a")
	h := registerRuntimePoolAuth(t, m, e, "-human", "user-human", "entitlement-human")
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	hctx, hop := admitRuntimePool(t, m, "pool-human", PoolResponses)
	hopts := ex.Options{Metadata: map[string]any{compactionRequestContextMetadataKey: hctx, ex.SessionAffinityProviderMetadataKey: "mixed", ex.SessionAffinityModelMetadataKey: runtimePoolModel}, Headers: http.Header{"Session-Id": []string{"same-conversation"}}}
	if err := selector.RecordCompactionOutput(h.ID, hopts, []byte(`{"output":[{"type":"compaction","encrypted_content":"human-signed"}]}`)); err != nil {
		t.Fatal(err)
	}
	hop.Finish()
	ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
	input := []byte(`{"model":"pool-runtime-model","input":[{"type":"compaction","encrypted_content":"human-signed"}]}`)
	opts := ex.Options{OriginalRequest: input, Metadata: map[string]any{}, Headers: http.Header{"Session-Id": []string{"same-conversation"}}}
	_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: input}, opts)
	if err == nil || len(e.sends) != 0 {
		t.Fatalf("foreign signed block escaped namespace: err=%v sends=%v", err, e.sends)
	}
	op.Finish()
	if poolScopedProvider(ctx, "mixed") == poolScopedProvider(hctx, "mixed") {
		t.Fatal("conversation/parent/cursor namespace crossed pools")
	}
	if poolScopedProvider(context.Background(), "mixed") != "mixed" {
		t.Fatal("legacy namespace changed")
	}
}

func TestPoolLiveTransferAndExactRequestMutation(t *testing.T) {
	m := runtimePoolManager(t, 1, nil)
	e := &runtimePoolExecutor{provider: "codex"}
	human := registerRuntimePoolAuth(t, m, e, "-human", "user-human", "entitlement-human")
	registry.GetGlobalRegistry().UnregisterClient(human.ID) // live must not require ordinary model advertisement
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, op, err := m.BeginPoolOperation(parent, "pool-human", runtimePoolModel, PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.FinishLive)
	selected, err := m.SelectPoolLiveAuth(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"sdp":"fixture-offer","session":{"model":"pool-runtime-model"}}`)
	req, err := m.NewPoolLiveRequest(ctx, selected, "", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.SendPoolLiveRequest(req.Clone(req.Context()))
	requirePoolStatus(t, err, 503)
	req.Header.Set("X-External-Mutation", "deny")
	_, err = m.SendPoolLiveRequest(req)
	requirePoolStatus(t, err, 503)
	req, err = m.NewPoolLiveRequest(ctx, selected, "", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := m.SendPoolLiveRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if err = resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err = op.TransferToLive("call_test"); err != nil {
		t.Fatal(err)
	}
	cancel()
	op.Finish()
	_, _, err = m.BeginPoolOperation(context.Background(), "pool-human", runtimePoolModel, PoolLiveCall)
	requirePoolStatus(t, err, 429)
	join, err := m.NewPoolLiveRequest(ctx, selected, "call_test", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckKeyPolicySend(join); err != nil {
		t.Fatal(err)
	}
	op.FinishLive()
	op.FinishLive()
	_, next := admitRuntimePool(t, m, "pool-human", PoolLiveCall)
	next.Finish()
}
