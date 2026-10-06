package pluginhost

import (
	"context"
	"fmt"
	"strings"
)

// BeginPluginDelete installs a reversible call tombstone without waiting for
// active calls or for a configuration reload. It reserves the apply slot through
// EndPluginDelete so a reload cannot replace or resurrect the target mid-delete.
// A concurrent reload/deletion returns a conflict rather than blocking management.
func (h *Host) BeginPluginDelete(id string) bool {
	if h == nil {
		return true
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	// Never wait for applyMu while the caller holds a management lock.
	select {
	case h.applyMu <- struct{}{}:
	default:
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.deleting[id] {
		h.unlockApply()
		return false
	}
	if h.deleting == nil {
		h.deleting = make(map[string]bool)
	}
	h.deleting[id] = true
	for _, client := range h.pluginDeleteClientsLocked(id) {
		client.beginDrain()
	}
	return true
}

// EndPluginDelete clears the tombstone and restores call admission if a drain
// was canceled. Successfully unloaded clients are no longer in the runtime.
func (h *Host) EndPluginDelete(id string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if !h.deleting[id] {
		h.mu.Unlock()
		return
	}
	delete(h.deleting, id)
	for _, client := range h.pluginDeleteClientsLocked(id) {
		client.endDrain()
	}
	h.mu.Unlock()
	h.unlockApply()
}

func (h *Host) pluginDeleteClientsLocked(id string) []*guardedPluginClient {
	var clients []*guardedPluginClient
	plugins := append([]*loadedPlugin{h.loaded[id]}, h.retired[id]...)
	for _, plugin := range plugins {
		if plugin == nil {
			continue
		}
		if client, ok := plugin.client.(*guardedPluginClient); ok {
			clients = append(clients, client)
		}
	}
	return clients
}

// UnloadPluginForDeleteContext drains before detaching, unlike shutdown's
// UnloadPluginContext. Cancellation leaves the plugin loaded; the caller clears
// the tombstone with EndPluginDelete. No handler-wide lock may be held here.
func (h *Host) UnloadPluginForDeleteContext(ctx context.Context, id string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if h == nil {
		return nil
	}
	// BeginPluginDelete owns applyMu until EndPluginDelete, including the
	// caller's final file/config commit. Do not reacquire it here.
	h.mu.Lock()
	if !h.deleting[id] {
		h.mu.Unlock()
		return fmt.Errorf("plugin deletion has not been started")
	}
	clients := h.pluginDeleteClientsLocked(id)
	idle := make([]<-chan struct{}, 0, len(clients))
	for _, client := range clients {
		idle = append(idle, client.beginDrain())
	}
	// A canceled asynchronous load still owns its library until cleanup exits.
	// Do not remove its file while that ownership is unresolved.
	loading := h.loading[id] != nil
	h.mu.Unlock()
	if loading {
		return fmt.Errorf("plugin is still loading")
	}
	for _, done := range idle {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.unloadPluginLocked(ctx, id)
	return nil
}

func (c *guardedPluginClient) beginDrain() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.draining = true
	if c.calls == 0 {
		done := make(chan struct{})
		close(done)
		return done
	}
	return c.idle
}

func (c *guardedPluginClient) endDrain() {
	c.mu.Lock()
	c.draining = false
	c.mu.Unlock()
}
