package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

type poolTransitionTestHook struct {
	mu        sync.Mutex
	entries   []*log.Entry
	onWarning func(*log.Entry)
}

func (h *poolTransitionTestHook) Levels() []log.Level { return log.AllLevels }
func (h *poolTransitionTestHook) Fire(entry *log.Entry) error {
	h.mu.Lock()
	h.entries = append(h.entries, entry)
	h.mu.Unlock()
	if h.onWarning != nil && entry.Message == "native credential identity moved between pools; credential quarantined" {
		h.onWarning(entry)
	}
	return nil
}
func (h *poolTransitionTestHook) count(label string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, entry := range h.entries {
		if entry.Message == "native credential identity moved between pools; credential quarantined" && entry.Data["credential_label"] == label {
			count++
		}
	}
	return count
}

func installPoolTransitionHook(t *testing.T) *poolTransitionTestHook {
	t.Helper()
	logger := log.StandardLogger()
	previous := logger.ReplaceHooks(make(log.LevelHooks))
	hook := &poolTransitionTestHook{}
	logger.AddHook(hook)
	t.Cleanup(func() { logger.ReplaceHooks(previous) })
	return hook
}

func TestPoolIdentityTransitionQuarantinesBothPoolsAndStaleAttempts(t *testing.T) {
	hook := installPoolTransitionHook(t)
	m := runtimePoolManager(t, 2, nil)
	e := &runtimePoolExecutor{provider: "codex", identities: make(map[string]NativePoolIdentity)}
	a := registerRuntimePoolAuth(t, m, e, "-transition-a", "user-a", "entitlement-a")
	b := registerRuntimePoolAuth(t, m, e, "-transition-b", "user-b", "entitlement-b")
	h := registerRuntimePoolAuth(t, m, e, "-transition-human", "user-human", "entitlement-human")
	m.mu.Lock()
	m.auths[a.ID].Label = "transition-A"
	m.mu.Unlock()
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}

	ctx, op := admitRuntimePool(t, m, "pool-a", PoolResponses)
	ctx, err := m.poolEligibilityContext(ctx, op)
	if err != nil {
		t.Fatal(err)
	}
	staleCtx, _, err := m.poolAttemptContext(ctx, a, runtimePoolModel)
	if err != nil {
		t.Fatal(err)
	}

	current, ok := m.GetByID(a.ID)
	if !ok {
		t.Fatal("transition credential missing")
	}
	current.SetMetadata("access_token", "rotated-transition-a")
	e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human"}
	if _, err := m.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}

	before := len(e.sends)
	newCtx, newOp := admitRuntimePool(t, m, "pool-b", PoolResponses)
	if _, err := m.Execute(newCtx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{}); err != nil {
		t.Fatal(err)
	}
	newOp.Finish()
	if !m.poolCredentialQuarantined(a.ID) {
		t.Fatal("cross-pool identity transition was not quarantined")
	}
	if got := e.sends[before:]; len(got) != 1 || got[0] != b.ID {
		t.Fatalf("new operation did not select unchanged same-pool B: %v", got)
	}

	stale := current.Clone()
	stale.SetMetadata("account_id", "entitlement-a")
	req, err := http.NewRequestWithContext(staleCtx, http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", bytes.NewReader([]byte(runtimePoolPayload)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+stale.MetadataString("access_token"))
	req.Header.Set("Chatgpt-Account-Id", "entitlement-a")
	if err := CheckNativePoolSend(req); err == nil {
		t.Fatal("stale in-flight attempt bypassed transition quarantine")
	}

	humanCtx, humanOp := admitRuntimePool(t, m, "pool-human", PoolResponses)
	if _, err := m.Execute(humanCtx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{}); err != nil {
		t.Fatal(err)
	}
	humanOp.Finish()
	if got := e.sends[len(e.sends)-1]; got != h.ID {
		t.Fatalf("unchanged human credential was not allowed: got %s want %s", got, h.ID)
	}
	if got := hook.count("transition-A"); got != 1 {
		t.Fatalf("transition warning count=%d want 1", got)
	}
	op.Finish()
}

// These regressions protect the configured-owner trust boundary through the
// real manager acquisition, eligibility, execution and final-send paths.
func TestPoolIdentityTransitionRetainsKnownOwnerThroughUnownedProof(t *testing.T) {
	for _, invalidation := range []string{"cached-refresh", "material-update", "executor-refresh", "material-and-executor-refresh"} {
		t.Run(invalidation, func(t *testing.T) {
			hook := installPoolTransitionHook(t)
			m := runtimePoolManager(t, 1, nil)
			e := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
			b := registerRuntimePoolAuth(t, m, e, "-b", "user-b", "entitlement-b")
			h := registerRuntimePoolAuth(t, m, e, "-h", "user-human", "entitlement-human")
			a.Label = "lineage-A"
			if _, err := m.Update(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.acquirePoolProof(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			z := NativePoolIdentity{Provider: "codex", AccountID: "unconfigured-user-z", EntitlementID: "unconfigured-entitlement-z"}
			current, _ := m.GetByID(a.ID)
			current.SetMetadata("access_token", "lineage-z")
			e.identities[a.ID] = z
			if _, err := m.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			current, proof, err := m.acquirePoolProof(context.Background(), current)
			if err != nil || !samePoolIdentity(proof.identity, z) {
				t.Fatalf("complete unowned proof was not published: proof=%+v err=%v", proof.identity, err)
			}
			if m.poolCredentialQuarantined(a.ID) || hook.count(a.Label) != 0 {
				t.Fatal("unowned identity incorrectly quarantined before another configured owner was proven")
			}
			// An unowned candidate is not a global denial: valid B and H still send.
			assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human"}
			if invalidation == "material-update" || invalidation == "material-and-executor-refresh" {
				current.SetMetadata("access_token", "lineage-h")
				if _, err := m.Update(context.Background(), current); err != nil {
					t.Fatal(err)
				}
			}
			if invalidation == "executor-refresh" || invalidation == "material-and-executor-refresh" {
				if err := m.RegisterNativePoolExecutor(e); err != nil {
					t.Fatal(err)
				}
			}
			current, _ = m.GetByID(a.ID)
			// Force native reacquisition even in the valid-active-Z cache case.
			current.RejectedAccessToken = current.MetadataString("access_token")
			_, _, err = m.acquirePoolProof(context.Background(), current)
			if !errors.Is(err, errPoolCredentialQuarantined) || !m.poolCredentialQuarantined(a.ID) {
				t.Errorf("A -> complete unowned Z -> H lost the known agent owner: err=%v quarantined=%v", err, m.poolCredentialQuarantined(a.ID))
			}
			assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			if got := hook.count(a.Label); got != 1 {
				t.Errorf("lineage warning count=%d want 1", got)
			}
		})
	}
}

func assertPoolTransitionControls(t *testing.T, m *Manager, e *runtimePoolExecutor, excluded, agent, human string) {
	t.Helper()
	for _, control := range []struct{ key, want string }{{"pool-a", agent}, {"pool-human", human}} {
		ctx, op := admitRuntimePool(t, m, control.key, PoolResponses)
		before := len(e.sends)
		_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
		op.Finish()
		if err != nil {
			t.Errorf("valid %s control failed: %v", control.key, err)
			continue
		}
		if got := e.sends[before:]; len(got) != 1 || got[0] != control.want {
			t.Errorf("%s sends=%v want only %s, never moved credential %s", control.key, got, control.want, excluded)
		}
	}
}

func TestPoolIdentityTransitionWarnsOncePerCredentialGeneration(t *testing.T) {
	for _, change := range []string{"material", "registration"} {
		t.Run(change, func(t *testing.T) {
			hook := installPoolTransitionHook(t)
			m := runtimePoolManager(t, 1, nil)
			e := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
			b := registerRuntimePoolAuth(t, m, e, "-b", "user-b", "entitlement-b")
			h := registerRuntimePoolAuth(t, m, e, "-h", "user-human", "entitlement-human")
			a.Label = "generation-A"
			var warningGenerations []string
			hook.onWarning = func(entry *log.Entry) {
				if entry.Data["credential_label"] != a.Label {
					return
				}
				if len(entry.Data) != 4 || entry.Data["old_pool"] != "agents" || entry.Data["new_pool"] != "humans" {
					t.Errorf("unsafe or unexpected warning fields: %v", entry.Data)
				}
				warningGenerations = append(warningGenerations, fmt.Sprint(entry.Data["credential_generation"]))
				// A hook must be able to reacquire any native acquisition lock;
				// TryLock proves availability without deliberately deadlocking.
				if !m.mu.TryLock() {
					t.Error("warning hook retained manager lock")
				} else {
					m.mu.Unlock()
				}
				if !m.poolRuntime.mu.TryLock() {
					t.Error("warning hook retained pool runtime lock")
				} else {
					m.poolRuntime.mu.Unlock()
				}
				v, ok := m.poolRuntime.acquisitions.Load(a.ID)
				if !ok || !v.(*sync.Mutex).TryLock() {
					t.Error("warning hook retained credential acquisition lock")
				} else {
					v.(*sync.Mutex).Unlock()
				}
			}
			if _, err := m.Update(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.acquirePoolProof(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			current, _ := m.GetByID(a.ID)
			current.SetMetadata("access_token", "generation-h")
			e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human"}
			if _, err := m.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.acquirePoolProof(context.Background(), current); !errors.Is(err, errPoolCredentialQuarantined) {
				t.Fatalf("initial transition err=%v", err)
			}
			current, _ = m.GetByID(a.ID)
			firstGeneration := fmt.Sprintf("%d:%d", current.RegistrationEpoch, current.CredentialVersion)
			for range 2 {
				assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			}
			if got := hook.count(a.Label); got != 1 {
				t.Fatalf("same-generation warnings=%d want 1", got)
			}
			current, _ = m.GetByID(a.ID)
			previousEpoch, previousVersion := current.RegistrationEpoch, current.CredentialVersion
			if change == "material" {
				current.SetMetadata("access_token", "generation-h-updated")
			} else {
				// Exercise the accepted public replacement epoch independently of
				// material version; neither token hashes nor version alone suffice.
				current.RegistrationEpoch++
			}
			current, err := m.Update(context.Background(), current)
			if err != nil {
				t.Fatal(err)
			}
			if change == "registration" && (current.RegistrationEpoch == previousEpoch || current.CredentialVersion != previousVersion) {
				t.Fatal("fixture did not isolate registration generation")
			}
			acquisitions := e.acquisitions
			if _, _, err := m.acquirePoolProof(context.Background(), current); !errors.Is(err, errPoolCredentialQuarantined) {
				t.Fatalf("updated quarantined generation err=%v", err)
			}
			if e.acquisitions != acquisitions {
				t.Fatal("sticky quarantine unexpectedly acquired a new native proof")
			}
			for range 2 {
				assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			}
			if got := hook.count(a.Label); got != 2 {
				t.Errorf("updated-generation warnings=%d want exactly 2 total", got)
			}
			// Ordinary runtime mutations and executor cache invalidation do not
			// reset quarantine or create another credential generation.
			current, _ = m.GetByID(a.ID)
			current.StatusMessage = "ordinary runtime update"
			if _, err := m.UpdateRefreshedAuth(context.Background(), current, current.Clone()); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			if got := hook.count(a.Label); got != 2 || !m.poolCredentialQuarantined(a.ID) {
				t.Errorf("ordinary refresh/cache invalidation: warnings=%d quarantined=%v", got, m.poolCredentialQuarantined(a.ID))
			}
			secondGeneration := fmt.Sprintf("%d:%d", current.RegistrationEpoch, current.CredentialVersion)
			if len(warningGenerations) != 2 || warningGenerations[0] != firstGeneration || warningGenerations[1] != secondGeneration || firstGeneration == secondGeneration {
				t.Errorf("warning generations=%v want [%s %s]", warningGenerations, firstGeneration, secondGeneration)
			}
		})
	}
}

func TestPoolIdentityTransitionAllowsFirstOwnerAndSamePoolUpdates(t *testing.T) {
	for _, scenario := range []struct {
		name, account, entitlement, nextAccount, nextEntitlement, key string
	}{
		{"unowned-to-first-human", "unowned-user", "unowned-entitlement", "user-human", "entitlement-human", "pool-human"},
		{"same-pool", "user-a", "entitlement-a", "user-b", "entitlement-b", "pool-a"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			hook := installPoolTransitionHook(t)
			m := runtimePoolManager(t, 1, nil)
			e := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, e, "-a", scenario.account, scenario.entitlement)
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			if _, _, err := m.acquirePoolProof(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			current, _ := m.GetByID(a.ID)
			current.SetMetadata("access_token", "allowed-transition")
			e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: scenario.nextAccount, EntitlementID: scenario.nextEntitlement}
			if _, err := m.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			ctx, op := admitRuntimePool(t, m, scenario.key, PoolResponses)
			_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
			op.Finish()
			if err != nil || len(e.sends) != 1 || e.sends[0] != a.ID || m.poolCredentialQuarantined(a.ID) || hook.count(a.Label) != 0 {
				t.Fatalf("legitimate transition denied: err=%v sends=%v quarantined=%v", err, e.sends, m.poolCredentialQuarantined(a.ID))
			}
		})
	}
}

func TestPoolIdentityTransitionConservativeOwnerRequiresExactMembership(t *testing.T) {
	for _, partial := range []struct{ name, account, entitlement string }{
		{"account-only", "user-a", "unowned-entitlement"},
		{"entitlement-only", "unowned-user", "entitlement-a"},
	} {
		t.Run(partial.name, func(t *testing.T) {
			m := runtimePoolManager(t, 1, nil)
			e := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, e, "-a", partial.account, partial.entitlement)
			b := registerRuntimePoolAuth(t, m, e, "-b", "user-b", "entitlement-b")
			h := registerRuntimePoolAuth(t, m, e, "-h", "user-human", "entitlement-human")
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			current, _ := m.GetByID(a.ID)
			current.SetMetadata("access_token", "partial-to-human")
			e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human"}
			if _, err := m.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			assertPoolTransitionControls(t, m, e, a.ID, b.ID, h.ID)
			if !m.poolCredentialQuarantined(a.ID) {
				t.Fatal("single configured identity atom did not retain conservative owner")
			}
		})
	}
}

func TestPoolIdentityTransitionRemovalResetsQuarantine(t *testing.T) {
	m := runtimePoolManager(t, 1, nil)
	e := &runtimePoolExecutor{provider: "codex"}
	a := registerRuntimePoolAuth(t, m, e, "-a", "user-a", "entitlement-a")
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.acquirePoolProof(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	current, _ := m.GetByID(a.ID)
	current.SetMetadata("access_token", "removed-to-human")
	e.identities[a.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-human", EntitlementID: "entitlement-human"}
	if _, err := m.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.acquirePoolProof(context.Background(), current); !errors.Is(err, errPoolCredentialQuarantined) {
		t.Fatalf("initial quarantine err=%v", err)
	}
	// Remove is runtime-only (nil store); it does not delete disk credentials.
	m.Remove(context.Background(), a.ID)
	a = registerRuntimePoolAuth(t, m, e, "-a", "user-human", "entitlement-human")
	ctx, op := admitRuntimePool(t, m, "pool-human", PoolResponses)
	_, err := m.Execute(ctx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
	op.Finish()
	if err != nil || len(e.sends) != 1 || e.sends[0] != a.ID || m.poolCredentialQuarantined(a.ID) {
		t.Fatalf("record removal did not reset quarantine: err=%v sends=%v", err, e.sends)
	}
}

func TestPoolIdentityTransitionRetainsTransferredLiveLease(t *testing.T) {
	m := runtimePoolManager(t, 1, nil)
	e := &runtimePoolExecutor{provider: "codex", identities: make(map[string]NativePoolIdentity)}
	h := registerRuntimePoolAuth(t, m, e, "-live-transition-human", "user-human", "entitlement-human")
	registry.GetGlobalRegistry().UnregisterClient(h.ID)
	if err := m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}

	ctx, op, err := m.BeginPoolOperation(context.Background(), "pool-human", runtimePoolModel, PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := m.SelectPoolLiveAuth(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"sdp":"fixture-offer","session":{"model":"pool-runtime-model"}}`)
	req, err := m.NewPoolLiveRequest(ctx, selected, "", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := m.SendPoolLiveRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if err := op.TransferToLive("transition-call"); err != nil {
		t.Fatal(err)
	}

	current, ok := m.GetByID(h.ID)
	if !ok {
		t.Fatal("live transition credential missing")
	}
	current.SetMetadata("access_token", "rotated-live-transition-human")
	e.identities[h.ID] = NativePoolIdentity{Provider: "codex", AccountID: "user-a", EntitlementID: "entitlement-a"}
	if _, err := m.Update(context.Background(), current); err != nil {
		t.Fatal(err)
	}

	agentCtx, agentOp := admitRuntimePool(t, m, "pool-a", PoolResponses)
	_, _ = m.Execute(agentCtx, []string{"codex"}, ex.Request{Model: runtimePoolModel, Payload: []byte(runtimePoolPayload)}, ex.Options{})
	agentOp.Finish()
	if !m.poolCredentialQuarantined(h.ID) {
		t.Fatal("live credential transition was not quarantined")
	}
	if op.pool.selectedID != h.ID || !op.pool.live || op.pool.ctx.Err() == nil {
		t.Fatal("live operation was repinned or left active after transition")
	}
	if err := op.TransferToLive("replacement-call"); err == nil {
		t.Fatal("quarantined live operation accepted a repin")
	}
	_, _, err = m.BeginPoolOperation(context.Background(), "pool-human", runtimePoolModel, PoolLiveCall)
	requirePoolStatus(t, err, 429)
	op.Finish()
	_, _, err = m.BeginPoolOperation(context.Background(), "pool-human", runtimePoolModel, PoolLiveCall)
	requirePoolStatus(t, err, 429)
	op.FinishLive()
	_, next := admitRuntimePool(t, m, "pool-human", PoolLiveCall)
	next.Finish()
}
