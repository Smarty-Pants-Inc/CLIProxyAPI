package pluginhost

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
)

type modelStreamBridge struct {
	next    atomic.Uint64
	mu      sync.Mutex
	streams map[string]modelStreamEntry
}

type modelStreamEntry struct {
	ownerCallbackID  string
	chunks           <-chan handlers.ModelExecutionChunk
	cancel           context.CancelFunc
	done             chan struct{}
	stopScopeCleanup func()
	stopCancel       func() bool
}

func newModelStreamBridge() *modelStreamBridge {
	return &modelStreamBridge{streams: make(map[string]modelStreamEntry)}
}

func (b *modelStreamBridge) open(ownerCallbackID string, chunks <-chan handlers.ModelExecutionChunk, cancel context.CancelFunc) string {
	if b == nil || chunks == nil {
		if cancel != nil {
			cancel()
		}
		return ""
	}
	id := strconv.FormatUint(b.next.Add(1), 10)
	b.mu.Lock()
	b.streams[id] = modelStreamEntry{ownerCallbackID: ownerCallbackID, chunks: chunks, cancel: cancel, done: make(chan struct{})}
	b.mu.Unlock()
	return id
}

// attachLifetime transfers the pre-execution cleanup to the published stream.
func (b *modelStreamBridge) attachLifetime(id string, ctx context.Context, stopScopeCleanup func()) bool {
	b.mu.Lock()
	entry, ok := b.streams[id]
	if !ok || ctx.Err() != nil {
		b.mu.Unlock()
		stopScopeCleanup()
		b.close(id)
		return false
	}
	entry.stopScopeCleanup = stopScopeCleanup
	entry.stopCancel = context.AfterFunc(ctx, func() { b.close(id) })
	b.streams[id] = entry
	b.mu.Unlock()
	return true
}

func (b *modelStreamBridge) read(ctx context.Context, id, ownerCallbackID string) (handlers.ModelExecutionChunk, bool, error) {
	if b == nil {
		return handlers.ModelExecutionChunk{}, true, fmt.Errorf("model stream bridge is unavailable")
	}
	if id == "" {
		return handlers.ModelExecutionChunk{}, true, fmt.Errorf("model stream id is required")
	}
	b.mu.Lock()
	entry, ok := b.streams[id]
	b.mu.Unlock()
	if !ok || entry.ownerCallbackID != ownerCallbackID {
		return handlers.ModelExecutionChunk{}, true, fmt.Errorf("model stream is not open for the owning callback")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		b.close(id)
		return handlers.ModelExecutionChunk{}, true, ctx.Err()
	case <-entry.done:
		return handlers.ModelExecutionChunk{}, true, fmt.Errorf("model stream is closed")
	case chunk, okRead := <-entry.chunks:
		// A ready chunk must not win a race against owner cancellation/explicit close.
		if err := ctx.Err(); err != nil {
			b.close(id)
			return handlers.ModelExecutionChunk{}, true, err
		}
		select {
		case <-entry.done:
			return handlers.ModelExecutionChunk{}, true, fmt.Errorf("model stream is closed")
		default:
		}
		if !okRead {
			b.close(id)
			return handlers.ModelExecutionChunk{}, true, nil
		}
		if chunk.Err != nil {
			b.close(id)
			return chunk, true, nil
		}
		return chunk, false, nil
	}
}

func (b *modelStreamBridge) closeOwned(id, ownerCallbackID string) error {
	if id == "" {
		return fmt.Errorf("model stream id is required")
	}
	b.mu.Lock()
	entry, ok := b.streams[id]
	if !ok || entry.ownerCallbackID != ownerCallbackID {
		b.mu.Unlock()
		return fmt.Errorf("model stream is not open for the owning callback")
	}
	delete(b.streams, id)
	b.mu.Unlock()
	closeModelStreamEntry(entry)
	return nil
}

func closeModelStreamEntry(entry modelStreamEntry) {
	if entry.done != nil {
		close(entry.done)
	}
	if entry.stopCancel != nil {
		entry.stopCancel()
	}
	if entry.stopScopeCleanup != nil {
		entry.stopScopeCleanup()
	}
	if entry.cancel != nil {
		entry.cancel()
	}
}

func (b *modelStreamBridge) close(id string) {
	if b == nil || id == "" {
		return
	}
	b.mu.Lock()
	entry := b.streams[id]
	delete(b.streams, id)
	b.mu.Unlock()
	closeModelStreamEntry(entry)
}
