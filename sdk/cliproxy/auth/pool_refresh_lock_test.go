package auth

import (
	"context"
	"errors"
	"testing"
)

// The proof service may rotate the same refresh token as ordinary refresh.
// Verify ownership of the actual shared lock without timing/scheduling sleeps.
type refreshLockPoolExecutor struct {
	runtimePoolExecutor
	manager *Manager
}

func (e *refreshLockPoolExecutor) AcquirePoolIdentity(ctx context.Context, a *Auth) (*Auth, NativePoolIdentity, error) {
	value, ok := e.manager.refreshLocks.Load(a.ID)
	if !ok {
		return nil, NativePoolIdentity{}, errors.New("proof did not acquire credential refresh lock")
	}
	lock := value.(*authRefreshLock)
	if lock.mu.TryLock() {
		lock.mu.Unlock()
		return nil, NativePoolIdentity{}, errors.New("proof did not hold credential refresh lock")
	}
	updated, identity, err := e.runtimePoolExecutor.AcquirePoolIdentity(ctx, a)
	if err == nil {
		updated.SetMetadata("access_token", "proof-rotated-access")
		updated.SetMetadata("refresh_token", "proof-rotated-refresh")
	}
	return updated, identity, err
}

// Keep: rotating-credential data safety at the ordinary-refresh/proof boundary.
func TestPoolProofSharesCredentialRefreshLock(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			m := runtimePoolManager(t, 1, nil)
			e := &refreshLockPoolExecutor{runtimePoolExecutor: runtimePoolExecutor{provider: provider}, manager: m}
			account, entitlement := "user-a", "entitlement-a"
			if provider == "claude" {
				account, entitlement = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
			}
			a := registerRuntimePoolAuth(t, m, &e.runtimePoolExecutor, "-a", account, entitlement)
			if err := m.RegisterNativePoolExecutor(e); err != nil {
				t.Fatal(err)
			}
			updated, _, err := m.acquirePoolProof(context.Background(), a)
			if err != nil {
				t.Fatalf("acquire proof under shared refresh lock: %v", err)
			}
			value, _ := m.refreshLocks.Load(a.ID)
			lock := value.(*authRefreshLock)
			if !lock.mu.TryLock() {
				t.Fatal("proof retained credential refresh lock after return")
			}
			lock.mu.Unlock()
			if updated.MetadataString("refresh_token") != "proof-rotated-refresh" {
				t.Fatal("rotated refresh token was not published")
			}
			// An ordinary request that rejected the pre-proof token must use the newly
			// published token, not call Refresh with the old rotating credential again.
			refreshed, err := m.refreshAuthForRequest(context.Background(), a.ID, a.MetadataString("access_token"))
			if err != nil {
				t.Fatalf("ordinary refresh did not reuse proof result: %v", err)
			}
			if refreshed.MetadataString("access_token") != "proof-rotated-access" {
				t.Fatal("ordinary refresh lost proof rotation")
			}
		})
	}
}
