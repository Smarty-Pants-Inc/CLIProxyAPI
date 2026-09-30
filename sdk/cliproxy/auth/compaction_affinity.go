package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
)

const (
	compactionAffinityMetadataKey      = "compaction_affinity"
	compactionAffinityStoreMetadataKey = "compaction_affinity_store"
)

// Pick keeps every signed compaction input on its observed producing account.
// Signer evidence is independent of mutable conversation routing aliases.
func (s *SessionAffinitySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	rawOrigin, captured := opts.Metadata[compactionAffinityStoreMetadataKey]
	origin, _ := rawOrigin.(*SessionAffinitySelector)
	if !captured {
		origin = s
		opts.Metadata[compactionAffinityStoreMetadataKey] = origin
	}
	if origin == nil {
		// The request began without local affinity. Enabling it mid-request
		// must not attach a new local authority to that request.
		return s.fallback.Pick(ctx, provider, model, opts, auths)
	}
	authID, errPrepare := origin.prepareCompactionAffinity(provider, model, opts)
	if errPrepare != nil {
		return nil, errPrepare
	}
	if authID != "" {
		pinnedAuths := make([]*Auth, 0, 1)
		for _, candidate := range auths {
			if candidate != nil && candidate.ID == authID {
				pinnedAuths = append(pinnedAuths, candidate)
			}
		}
		if len(pinnedAuths) == 0 {
			return nil, compactedAuthUnavailableError()
		}
		auths = pinnedAuths
	}
	auth, errPick := origin.pick(ctx, provider, model, opts, auths)
	if errPick == nil && auth != nil {
		for _, key := range compactionAffinityKeys(opts) {
			origin.cache.Touch(key, auth.ID)
		}
	}
	if errState := origin.cache.PersistenceError(); errState != nil {
		return nil, affinityStateError()
	}
	return auth, errPick
}

// prepareSessionAffinitySelection also guards plugin scheduling, which can bypass
// Selector.Pick. It runs before candidates are filtered, using the existing pin
// that every execution retry path already honors.
func (m *Manager) prepareSessionAffinitySelection(provider, model string, opts cliproxyexecutor.Options) error {
	origin, captured := opts.Metadata[compactionAffinityStoreMetadataKey]
	if !captured {
		affinity, _ := m.Selector().(*SessionAffinitySelector)
		origin = affinity
		opts.Metadata[compactionAffinityStoreMetadataKey] = affinity
	}
	if affinity, ok := origin.(*SessionAffinitySelector); ok && affinity != nil {
		_, errPrepare := affinity.prepareCompactionAffinity(provider, model, opts)
		return errPrepare
	}
	return nil
}

// PrepareCompactionRequest captures request-owned signer authority before any
// attempt-local metadata clones. HTTP bootstrap reinvocations must reuse the
// returned options. A present typed nil store is an explicit negative decision;
// only an absent key permits origin discovery.
func (m *Manager) PrepareCompactionRequest(model string, opts cliproxyexecutor.Options) (cliproxyexecutor.Options, error) {
	routeModel := authSelectionModelFromOptions(opts, model)
	opts = ensureRequestedModelMetadata(opts, routeModel)
	if _, captured := opts.Metadata[compactionAffinityStoreMetadataKey]; !captured {
		var origin *SessionAffinitySelector
		if !m.HomeEnabled() {
			origin, _ = m.Selector().(*SessionAffinitySelector)
		}
		opts.Metadata[compactionAffinityStoreMetadataKey] = origin
	}
	opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
	opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = routeModel
	if errPrepare := m.prepareSessionAffinitySelection("mixed", routeModel, opts); errPrepare != nil {
		return opts, wrapRequestStopError(errPrepare)
	}
	m.prepareCompactionDuplexValidation(opts)
	return opts, nil
}

// IsLocalCompactionAffinityStop identifies local affinity failures without
// treating an ordinary upstream 5xx as a non-retryable bootstrap error.
// errors.As keeps the marker effective through execution and HTTP wrappers.
func IsLocalCompactionAffinityStop(err error) bool {
	if !isRequestStopError(err) {
		return false
	}
	var local *Error
	if !errors.As(err, &local) || local == nil {
		return false
	}
	switch local.Code {
	case "affinity_state_unavailable", "compaction_affinity_missing", "compaction_affinity_conflict":
		return true
	default:
		return false
	}
}

func (s *SessionAffinitySelector) prepareCompactionAffinity(provider, model string, opts cliproxyexecutor.Options) (string, error) {
	if errState := s.cache.PersistenceError(); errState != nil {
		return "", affinityStateError()
	}
	keys := compactionAffinityKeys(opts)
	if len(keys) == 0 {
		primaryID, _ := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
		primaryKey := provider + "::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + canonicalModelKey(model)
		if primaryID == "" || !s.cache.IsProtected(primaryKey) {
			return "", nil
		}
		authID, ok := s.cache.Get(primaryKey)
		if !ok {
			return "", compactedAuthUnavailableError()
		}
		return pinCompactionAuth(opts, authID)
	}

	authID := ""
	for _, key := range keys {
		signer, known := s.cache.Get(key)
		if !known {
			// Neither a newer explicit binding nor an approximate LCP trajectory
			// proves who signed an old/imported block. Never guess from either.
			return "", &Error{Code: "compaction_affinity_missing", Message: "signed compaction account is unknown; start a new conversation or recompact without the signed block", HTTPStatus: http.StatusConflict}
		}
		if !s.cache.IsProtected(key) {
			return "", affinityStateError()
		}
		if authID != "" && authID != signer {
			return "", &Error{Code: "compaction_affinity_conflict", Message: "compaction blocks belong to different accounts; recompact before continuing", HTTPStatus: http.StatusConflict}
		}
		authID = signer
	}
	if _, errPin := pinCompactionAuth(opts, authID); errPin != nil {
		return "", errPin
	}
	if primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata); primaryID != "" {
		primaryKey := provider + "::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + canonicalModelKey(model)
		if errProtect := s.cache.SetProtectedAliases(authID, primaryKey); errProtect != nil {
			if s.cache.PersistenceError() != nil {
				return "", affinityStateError()
			}
			return "", compactedAuthUnavailableError()
		}
	}
	for _, key := range keys {
		if retainedID, retained := s.cache.Get(key); !retained || retainedID != authID || !s.cache.IsProtected(key) {
			return "", compactedAuthUnavailableError()
		}
	}
	opts.Metadata[compactionAffinityMetadataKey] = keys
	return authID, nil
}

func pinCompactionAuth(opts cliproxyexecutor.Options, authID string) (string, error) {
	if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" && pinned != authID {
		return "", compactedAuthUnavailableError()
	}
	opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = authID
	return authID, nil
}

func affinityStateError() *Error {
	return &Error{Code: "affinity_state_unavailable", Message: "session affinity state is unavailable; refusing to change accounts", HTTPStatus: http.StatusServiceUnavailable}
}

func compactedAuthUnavailableError() *Error {
	return &Error{Code: "auth_unavailable", Message: "signed compaction account is unavailable; refusing account failover", HTTPStatus: http.StatusServiceUnavailable}
}

func compactionAffinityKeys(opts cliproxyexecutor.Options) []string {
	keys := compactionBlockKeys(gjson.GetBytes(opts.OriginalRequest, "input"))
	gjson.GetBytes(opts.OriginalRequest, "messages").ForEach(func(_, message gjson.Result) bool {
		keys = mergeSessionAliases(keys, compactionBlockKeys(message.Get("content"))...)
		return true
	})
	return keys
}

// Each block has an independent key: changing list shape or ordinary turns must
// never bypass a known signer's constraint. Persist no block or conversation text.
func compactionBlockKeys(items gjson.Result) []string {
	var keys []string
	items.ForEach(func(_, item gjson.Result) bool {
		if item.Get("type").String() == "compaction" {
			block := item.Get("encrypted_content").String()
			if block == "" {
				block = item.Raw
			}
			digest := sha256.Sum256([]byte(block))
			keys = mergeSessionAliases(keys, fmt.Sprintf("compaction::%x", digest))
		}
		return true
	})
	return keys
}
