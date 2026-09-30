package auth

import (
	"context"
	"net/http"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// validateCompactionSelectedAuth checks replacement input against the actual
// selected account, without discovering a new authority or changing routing.
// In particular, a new pin after selection cannot make a B-signed block safe on A.
func validateCompactionSelectedAuth(ctx context.Context, authID string, opts cliproxyexecutor.Options) (err error) {
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
	return compactionCheckContext(ctx)
}
