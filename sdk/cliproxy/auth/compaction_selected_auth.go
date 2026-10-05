package auth

import (
	"context"
	"net/http"
	"sync"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

const compactionSelectionRefreshMetadataKey = "compaction_selection_refresh"

// A selection receipt saves only the immediately following unchanged dispatch
// publication, not a later admission. Shallow metadata clones share the one-use
// receipt; root preparation clears it and each selection installs a new receipt.
// Signer liveness and cancellation are still checked before consuming it.
type compactionSelectionRefresh struct {
	mu       sync.Mutex
	origin   *SessionAffinitySelector
	authID   string
	keys     []string
	consumed bool
}

func rememberCompactionSelectionRefresh(origin *SessionAffinitySelector, authID string, keys []string, opts cliproxyexecutor.Options) {
	if len(keys) == 0 || opts.Metadata == nil {
		return
	}
	opts.Metadata[compactionSelectionRefreshMetadataKey] = &compactionSelectionRefresh{
		origin: origin, authID: authID, keys: append([]string(nil), keys...),
	}
}

func consumeCompactionSelectionRefresh(ctx context.Context, origin *SessionAffinitySelector, authID string, keys []string, opts cliproxyexecutor.Options) (bool, error) {
	if err := compactionCheckContext(ctx); err != nil {
		return false, err
	}
	receipt, _ := opts.Metadata[compactionSelectionRefreshMetadataKey].(*compactionSelectionRefresh)
	if receipt == nil {
		return false, nil
	}
	receipt.mu.Lock()
	defer receipt.mu.Unlock()
	if err := compactionCheckContext(ctx); err != nil {
		return false, err
	}
	if receipt.consumed {
		return false, nil
	}
	// Even a changed dispatch consumes this selection's receipt. It cannot
	// become available again if another replacement restores the old input.
	receipt.consumed = true
	if receipt.origin != origin || receipt.authID != authID || len(receipt.keys) != len(keys) {
		return false, nil
	}
	for i, key := range keys {
		if receipt.keys[i] != key {
			return false, nil
		}
	}
	return true, nil
}

// refreshCompactionSignerBindings keeps publication synchronous and bounded to
// one protected batch, preserving sticky I/O and post-save retention checks.
func refreshCompactionSignerBindings(ctx context.Context, origin *SessionAffinitySelector, authID string, keys []string) error {
	if err := compactionCheckContext(ctx); err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	if err := origin.cache.touchProtectedBindings(ctx, authID, keys...); err != nil {
		if errContext := compactionCheckContext(ctx); errContext != nil {
			return errContext
		}
		return affinityStateError()
	}
	return compactionCheckContext(ctx)
}

// validateCompactionSelectedAuth checks final input against the actual selected
// account, then renews signer retention without discovering a new authority or
// changing routing. A replacement pin cannot make a B-signed block safe on A.
func validateCompactionSelectedAuth(ctx context.Context, authID string, opts cliproxyexecutor.Options) error {
	return validateCompactionSelectedAuthWithRefresh(ctx, authID, opts, false)
}

func validateCompactionSelectedAuthWithRefresh(ctx context.Context, authID string, opts cliproxyexecutor.Options, selection bool) (err error) {
	origin, _ := opts.Metadata[compactionAffinityStoreMetadataKey].(*SessionAffinitySelector)
	if origin == nil {
		// Absent authority and a captured negative decision both stay negative.
		return nil
	}
	defer func() { err = wrapRequestStopError(err) }()
	if source, ok := opts.Metadata[compactionRequestContextMetadataKey].(context.Context); ok && source != nil {
		ctx = source
	}
	if ctx == nil {
		ctx = context.Background()
	}
	keys, errCollect := compactionAffinityKeysChecked(ctx, opts)
	if errCollect != nil {
		return errCollect
	}
	if origin.cache == nil || origin.cache.PersistenceError() != nil {
		return affinityStateError()
	}
	for _, key := range keys {
		if errContext := compactionCheckContext(ctx); errContext != nil {
			return errContext
		}
		signer, known := origin.cache.Get(key)
		if !known || signer == "" {
			return &Error{Code: "compaction_affinity_missing", Message: "signed compaction account is unknown; start a new conversation or recompact without the signed block", HTTPStatus: http.StatusConflict}
		}
		if !origin.cache.IsProtected(key) {
			return affinityStateError()
		}
		if authID == "" || signer != authID {
			return &Error{Code: "compaction_affinity_conflict", Message: "signed compaction account does not match the selected account; recompact before continuing", HTTPStatus: http.StatusConflict}
		}
	}
	if origin.cache.PersistenceError() != nil {
		return affinityStateError()
	}
	if !selection {
		refreshed, errReceipt := consumeCompactionSelectionRefresh(ctx, origin, authID, keys, opts)
		if errReceipt != nil {
			return errReceipt
		}
		if refreshed {
			return compactionCheckContext(ctx)
		}
	}
	if errRefresh := refreshCompactionSignerBindings(ctx, origin, authID, keys); errRefresh != nil {
		return errRefresh
	}
	if selection {
		rememberCompactionSelectionRefresh(origin, authID, keys, opts)
	}
	return nil
}
