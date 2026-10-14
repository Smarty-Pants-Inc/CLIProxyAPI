package auth

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

type refreshPersistenceContextKey struct{}
type refreshPersistenceFence func(func() error) error

// PersistRefreshCredentials fences an executor's durable refresh write against the
// registration it started with. The caller must already hold its credential file
// lock; the manager read lock then excludes removal/re-registration through the write.
// Direct executor callers without a manager still require the file-existence fence.
func PersistRefreshCredentials(ctx context.Context, persist func() error) error {
	if ctx != nil {
		if fence, ok := ctx.Value(refreshPersistenceContextKey{}).(refreshPersistenceFence); ok {
			return fence(persist)
		}
	}
	return persist()
}

func (m *Manager) withRefreshPersistenceFence(ctx context.Context, base *Auth) context.Context {
	id, epoch := base.ID, base.RegistrationEpoch
	fence := refreshPersistenceFence(func(persist func() error) error {
		m.mu.RLock()
		defer m.mu.RUnlock()
		current := m.auths[id]
		if current == nil || current.RegistrationEpoch != epoch || m.authEpochs[id] != epoch {
			return codex.ErrRefreshNotPersisted
		}
		return persist()
	})
	return context.WithValue(ctx, refreshPersistenceContextKey{}, fence)
}
