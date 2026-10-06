package management

import "github.com/router-for-me/CLIProxyAPI/v8/internal/config"

type pluginOperationKind uint8

const (
	pluginOperationNone pluginOperationKind = iota
	pluginOperationInstalling
	pluginOperationDeleting
)

type pluginOperation struct {
	gen uint64
	op  pluginOperationKind
}
type pluginConfigLease struct {
	generations map[string]uint64
	blocked     bool
}

// Plugin generations are never removed: clearing a tombstone must not make an
// install or config snapshot admitted before DELETE current again.
// The Locked helpers require h.mu.
func (h *Handler) beginPluginOperationLocked(id string, op pluginOperationKind) uint64 {
	if h.pluginOperations == nil {
		h.pluginOperations = make(map[string]pluginOperation)
	}
	operation := h.pluginOperations[id]
	operation.gen++
	operation.op = op
	h.pluginOperations[id] = operation
	return operation.gen
}
func (h *Handler) pluginOperationCurrentLocked(id string, gen uint64) bool {
	return h.pluginOperations[id].gen == gen
}
func (h *Handler) endPluginOperationLocked(id string, gen uint64) {
	if h.pluginOperationCurrentLocked(id, gen) {
		operation := h.pluginOperations[id]
		operation.op = pluginOperationNone
		h.pluginOperations[id] = operation
	}
}

func (h *Handler) pluginConfigLeaseLocked(cfg *config.Config) pluginConfigLease {
	ids := make(map[string]struct{}, len(h.pluginOperations))
	for id := range h.pluginOperations {
		ids[id] = struct{}{}
	}
	if cfg != nil {
		for id := range cfg.Plugins.Configs {
			ids[id] = struct{}{}
		}
	}
	lease := pluginConfigLease{generations: make(map[string]uint64, len(ids))}
	for id := range ids {
		operation := h.pluginOperations[id]
		if operation.op == pluginOperationDeleting {
			// An unrelated config write may still run its hook during a drain, but
			// its snapshot must never apply the deleting plugin, even after the drain.
			if cfg != nil {
				if _, configured := cfg.Plugins.Configs[id]; configured {
					lease.blocked = true
				}
			}
			lease.generations[id] = operation.gen
			continue
		}
		lease.generations[id] = h.beginPluginOperationLocked(id, pluginOperationNone)
	}
	return lease
}
func (h *Handler) pluginConfigLeaseCurrentLocked(lease pluginConfigLease) bool {
	for id, gen := range lease.generations {
		if !h.pluginOperationCurrentLocked(id, gen) {
			return false
		}
	}
	return true
}
func (h *Handler) pluginConfigApplyGuard(lease pluginConfigLease) func() bool {
	return func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if lease.blocked || !h.pluginConfigLeaseCurrentLocked(lease) {
			return false
		}
		for id := range lease.generations {
			if h.pluginOperations[id].op == pluginOperationDeleting {
				return false
			}
		}
		return true
	}
}
func (h *Handler) pluginConfigApplyLease(cfg *config.Config) func() bool {
	h.mu.Lock()
	lease := h.pluginConfigLeaseLocked(cfg)
	h.mu.Unlock()
	return h.pluginConfigApplyGuard(lease)
}
