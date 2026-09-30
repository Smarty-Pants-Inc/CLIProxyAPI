package auth

import (
	"net/http"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// prepareCompactionDuplexValidation installs authority from the captured request
// origin, never from the Manager's current selector or mutable routing aliases.
// Call after root origin capture, before options are cloned for execution.
func (m *Manager) prepareCompactionDuplexValidation(opts cliproxyexecutor.Options) {
	if opts.Metadata == nil {
		return
	}
	origin, _ := opts.Metadata[compactionAffinityStoreMetadataKey].(*SessionAffinitySelector)
	if origin == nil {
		delete(opts.Metadata, cliproxyexecutor.CompactionAffinityValidatorMetadataKey)
		return
	}
	ctx := compactionContext(opts)
	opts.Metadata[cliproxyexecutor.CompactionAffinityValidatorMetadataKey] = func(authID string, payload []byte) (err error) {
		defer func() { err = wrapRequestStopError(err) }()
		keys, errCollect := compactionAffinityKeysChecked(ctx, cliproxyexecutor.Options{OriginalRequest: payload})
		if errCollect != nil {
			return errCollect
		}
		if len(keys) == 0 {
			return nil
		}
		if origin.cache == nil || origin.cache.PersistenceError() != nil {
			return affinityStateError()
		}
		signerID := ""
		for _, key := range keys {
			signer, known := origin.cache.Get(key)
			if !known || signer == "" {
				return &Error{Code: "compaction_affinity_missing", Message: "signed compaction account is unknown; start a new conversation or recompact without the signed block", HTTPStatus: http.StatusConflict}
			}
			if !origin.cache.IsProtected(key) {
				return affinityStateError()
			}
			if signerID != "" && signerID != signer {
				return &Error{Code: "compaction_affinity_conflict", Message: "compaction blocks belong to different accounts; recompact before continuing", HTTPStatus: http.StatusConflict}
			}
			signerID = signer
		}
		if origin.cache.PersistenceError() != nil {
			return affinityStateError()
		}
		if authID == "" || authID != signerID {
			return &Error{Code: "compaction_affinity_conflict", Message: "signed compaction account does not match this websocket; start a new connection on its producing account", HTTPStatus: http.StatusConflict}
		}
		// Each create/append/steer is a new admission on this socket. Do not
		// reuse the initial selection's receipt for these later messages.
		return refreshCompactionSignerBindings(ctx, origin, authID, keys)
	}
}
