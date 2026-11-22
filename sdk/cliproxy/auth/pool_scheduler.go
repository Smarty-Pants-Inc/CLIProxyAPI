package auth

import (
	"context"
	"strings"
)

func poolScopedProvider(ctx context.Context, provider string) string {
	if op := KeyPolicyFromContext(ctx); op.IsPoolOperation() {
		prefix := "pool:" + op.pool.pool.ID + "|"
		if !strings.HasPrefix(provider, prefix) {
			return prefix + provider
		}
	}
	return provider
}

// Called only under the existing scheduler lock. Pool cursors share the native
// ready/blocked indices and selection code, not a second scheduling controller.
func (m *modelScheduler) activatePoolCursors(ctx context.Context) func() {
	op := KeyPolicyFromContext(ctx)
	if !op.IsPoolOperation() {
		return func() {}
	}
	if m.poolCursors == nil {
		m.poolCursors = make(map[string]map[int]readyBucketCursorState)
	}
	snapshot := func() map[int]readyBucketCursorState {
		out := make(map[int]readyBucketCursorState, len(m.readyByPriority))
		for priority, b := range m.readyByPriority {
			if b != nil {
				out[priority] = readyBucketCursorState{snapshotReadyViewCursors(b.all), snapshotReadyViewCursors(b.ws)}
			}
		}
		return out
	}
	restore := func(states map[int]readyBucketCursorState) {
		for priority, b := range m.readyByPriority {
			if b != nil {
				state := states[priority]
				b.all.lastPicked, b.all.weightedState = state.all.lastPicked, state.all.weightedState
				b.ws.lastPicked, b.ws.weightedState = state.ws.lastPicked, state.ws.weightedState
			}
		}
	}
	legacy := snapshot()
	restore(m.poolCursors[op.pool.pool.ID])
	return func() { m.poolCursors[op.pool.pool.ID] = snapshot(); restore(legacy) }
}
