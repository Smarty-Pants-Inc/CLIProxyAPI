package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// Keep reason: the credential trust boundary must not weaken when upstream's
// partition-specific refresh patch meets the fork's stale-binding fence.
func TestManagerSIWCPatchRetainsForkBindingFence(t *testing.T) {
	for _, change := range []string{"none", "note", "outer-token"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			store := newMemoryAuthTestStore()
			manager := NewManager(store, nil, nil)
			base, err := manager.Register(ctx, &Auth{
				ID: "siwc-binding", Provider: "codex", Status: StatusActive,
				Metadata: map[string]any{
					"access_token": "outer-before", "refresh_token": "outer-refresh",
					"account_id": "same-account", "use_siwc": true,
					"siwc": map[string]any{"access_token": "siwc-before", "refresh_token": "siwc-refresh", "client_id": "test-client"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			refreshed := base.Clone()
			refreshed.SetMetadata("siwc", map[string]any{"access_token": "siwc-after", "refresh_token": "siwc-after-refresh", "client_id": "test-client"})
			refreshed.CodexRefreshPatch = codex.NewCredentialRefreshPatch(base.CloneMetadata(), refreshed.CloneMetadata(), false, true)
			current := base.Clone()
			if change == "note" {
				current.SetMetadata("note", "operator edit")
			} else if change == "outer-token" {
				current.SetMetadata("access_token", "outer-after")
			}
			if change != "none" {
				current, err = manager.Update(ctx, current)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !refreshed.CodexRefreshPatch.CanApplyTo(current.CloneMetadata()) {
				t.Fatal("test must exercise upstream's independently applicable SIWC partition")
			}
			_, err = manager.UpdateRefreshedAuth(ctx, base, refreshed)
			saved, _ := manager.GetByID(base.ID)
			if change == "outer-token" {
				if err == nil || !strings.Contains(err.Error(), "stale refresh credential binding") {
					t.Fatalf("concurrent outer rotation: want stale-binding error, got %v", err)
				}
				if saved.MetadataString("access_token") != "outer-after" || authSIWCTokenField(saved, "access_token") != "siwc-before" {
					t.Fatal("stale patch changed current credential partitions")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if saved.MetadataString("access_token") != "outer-before" || authSIWCTokenField(saved, "access_token") != "siwc-after" {
					t.Fatal("valid SIWC-only refresh did not preserve the outer partition")
				}
				if change == "note" && saved.MetadataString("note") != "operator edit" {
					t.Fatal("valid refresh lost a concurrent noncredential edit")
				}
			}
		})
	}
}
