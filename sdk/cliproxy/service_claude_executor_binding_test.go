package cliproxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// Keep: PR #166 regression at the watcher/native-pool trust boundary. An
// unrelated label Modify must not revoke work admitted to the Claude pool.
func TestClaudeAuthModifyPreservesInFlightPoolOperation(t *testing.T) {
	for _, kind := range []coreauth.PoolOperationKind{coreauth.PoolMessages, coreauth.PoolCountTokens} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			cfg, err := config.ParseConfigBytes([]byte(fmt.Sprintf(`ws-auth: true
access:
  api-keys: ["pool-key"]
  account-pools:
    - id: agents
      org: test
      class: agent
      max-in-flight: 1
      accounts:
        - {provider: claude, account-id: "11111111-1111-4111-8111-111111111111", entitlement-id: "22222222-2222-4222-8222-222222222222"}
  api-key-policies:
    - {key-sha256: "%x", pool: agents}
`, sha256.Sum256([]byte("pool-key")))))
			if err != nil {
				t.Fatal(err)
			}
			service := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
			service.coreManager.SetConfig(cfg)
			auth := &coreauth.Auth{ID: t.Name(), Provider: "claude", Status: coreauth.StatusActive,
				Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": "fixture-access"}}
			t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(auth.ID) })
			service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{Action: watcher.AuthUpdateActionAdd, ID: auth.ID, Auth: auth})
			first, _ := service.coreManager.Executor("claude")
			ctx, op, err := service.coreManager.BeginPoolOperation(context.Background(), "pool-key", "claude-sonnet-4-5", kind)
			if err != nil {
				t.Fatal(err)
			}
			defer op.Finish()
			updated, ok := service.coreManager.GetByID(auth.ID)
			if !ok {
				t.Fatal("auth missing before Modify")
			}
			updated.Label = "updated label"
			service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{Action: watcher.AuthUpdateActionModify, ID: auth.ID, Auth: updated})
			if err := ctx.Err(); err != nil {
				t.Fatalf("Claude auth Modify canceled in-flight pool operation: %v", err)
			}
			if current, _ := service.coreManager.Executor("claude"); current != first {
				t.Fatal("Claude auth Modify replaced native executor")
			}
			current, _ := service.coreManager.GetByID(auth.ID)
			if current.Label != updated.Label {
				t.Fatal("Modify was not applied")
			}
		})
	}
}

func TestClaudeExecutorPoolKeepGuardPreservesLegacyAndForcedRebind(t *testing.T) {
	for _, pools := range []bool{false, true} {
		t.Run(fmt.Sprintf("pools=%t", pools), func(t *testing.T) {
			cfg := &config.Config{}
			if pools {
				cfg.AccountPools = &[]config.AccountPool{}
			}
			service := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
			auth := &coreauth.Auth{ID: t.Name(), Provider: "claude", Status: coreauth.StatusActive}
			service.registerExecutorForAuth(auth, false)
			first, _ := service.coreManager.Executor("claude")
			service.registerExecutorForAuth(auth, false)
			second, _ := service.coreManager.Executor("claude")
			if (first == second) != pools {
				t.Fatalf("executor retained = %t, pools = %t", first == second, pools)
			}
			service.registerExecutorForAuth(auth, true)
			third, _ := service.coreManager.Executor("claude")
			if third == second {
				t.Fatal("forced rebind did not replace Claude executor")
			}
		})
	}
}
