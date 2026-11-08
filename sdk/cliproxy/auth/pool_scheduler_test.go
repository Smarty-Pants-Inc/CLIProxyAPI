package auth

import (
	"context"
	"fmt"
	"testing"

	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Trust-boundary regression: mixed provider rotation and each provider's ready
// cursor must be isolated together, including pinned and single-provider picks.
func TestPoolMixedSchedulerCursorNamespaces(t *testing.T) {
	for _, selector := range []Selector{&RoundRobinSelector{}, &WeightedRoundRobinSelector{}} {
		t.Run(fmt.Sprintf("%T", selector), func(t *testing.T) {
			m := runtimePoolManager(t, 1, selector)
			codex := &runtimePoolExecutor{provider: "codex"}
			a := registerRuntimePoolAuth(t, m, codex, "-a", "user-a", "entitlement-a")
			registerRuntimePoolAuth(t, m, codex, "-b", "user-b", "entitlement-b")
			h := registerRuntimePoolAuth(t, m, codex, "-h1", "user-human", "entitlement-human")
			registerRuntimePoolAuth(t, m, codex, "-h2", "user-human", "entitlement-human")
			claude := &runtimePoolExecutor{provider: "claude"}
			registerRuntimePoolAuth(t, m, claude, "-c", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222")
			for _, e := range []*runtimePoolExecutor{codex, claude} {
				if err := m.RegisterNativePoolExecutor(e); err != nil {
					t.Fatal(err)
				}
			}
			agent, agentOp := admitRuntimePool(t, m, "pool-a", PoolResponses)
			human, humanOp := admitRuntimePool(t, m, "pool-human", PoolResponses)
			for _, op := range []*KeyPolicyOperation{agentOp, humanOp} {
				if _, err := m.poolEligibilityContext(op.pool.ctx, op); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := m.snapshotAuths()
			newScheduler := func() *authScheduler {
				s := newAuthScheduler(selector)
				s.rebuild(snapshot)
				return s
			}
			shared := newScheduler()
			contexts := []context.Context{agent, human, context.Background()}
			pins := []string{a.ID, h.ID, a.ID}
			references := []*authScheduler{newScheduler(), newScheduler(), newScheduler()}
			pick := func(s *authScheduler, ctx context.Context, iteration int, pin string) string {
				t.Helper()
				opts := ex.Options{}
				var selected *Auth
				var err error
				if iteration%3 == 1 {
					selected, err = s.pickSingle(ctx, "codex", runtimePoolModel, opts, nil)
				} else {
					if iteration%3 == 2 {
						opts.Metadata = map[string]any{ex.PinnedAuthMetadataKey: pin}
					}
					selected, _, err = s.pickMixed(ctx, []string{"codex", "claude"}, runtimePoolModel, opts, nil)
				}
				if err != nil || selected == nil {
					t.Fatalf("pick %d: selected=%v err=%v", iteration, selected, err)
				}
				return selected.ID
			}
			for i := 0; i < 18; i++ {
				for index, ctx := range contexts {
					want := pick(references[index], ctx, i, pins[index])
					if got := pick(shared, ctx, i, pins[index]); got != want {
						t.Fatalf("iteration=%d namespace=%d shared=%q isolated=%q", i, index, got, want)
					}
				}
			}
		})
	}
}
