package auth

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"testing"
)

func TestKeyPolicyDoesNotChangeUnrelatedRefreshMerge(t *testing.T) {
	ctx := context.Background()
	m := NewManager(nil, nil, nil)
	m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), AllowedAuths: []string{"A"}}}}})
	base, err := m.Register(ctx, &Auth{ID: "B", Provider: "codex", Metadata: map[string]any{"access_token": "old", "note": "old"}})
	if err != nil {
		t.Fatal(err)
	}
	current := base.Clone()
	current.Metadata["note"] = "new"
	if _, err := m.Update(ctx, current); err != nil {
		t.Fatal(err)
	}
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "fresh"
	result, err := m.UpdateRefreshedAuth(ctx, base, refreshed)
	if err != nil || result.Metadata["note"] != "new" || result.Metadata["access_token"] != "fresh" {
		t.Fatalf("merge=%+v err=%v", result, err)
	}
}
