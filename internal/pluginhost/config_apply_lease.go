package pluginhost

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

type configApplyGuardKey struct{}

// WithConfigApplyGuard carries the management snapshot's operation lease across
// a reload hook. The guard is checked after acquiring the apply slot, not before
// waiting for DELETE to release it.
func WithConfigApplyGuard(ctx context.Context, guard func() bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, configApplyGuardKey{}, guard)
}

// SetConfigApplyLeaseSource coordinates config-driven loads (including watcher
// reloads) with management plugin operations. The source and its returned guard
// must not call back into Host. Neither is invoked while Host.mu is held.
func (h *Host) SetConfigApplyLeaseSource(source func(*config.Config) func() bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.configApplyLeaseSource = source
	h.mu.Unlock()
}

func (h *Host) configApplyGuard(ctx context.Context, cfg *config.Config) func() bool {
	if guard, ok := ctx.Value(configApplyGuardKey{}).(func() bool); ok && guard != nil {
		return guard
	}
	h.mu.Lock()
	source := h.configApplyLeaseSource
	h.mu.Unlock()
	if source != nil {
		return source(cfg)
	}
	return func() bool { return true }
}
