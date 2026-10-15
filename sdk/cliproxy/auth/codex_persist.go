package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// IsCodexAuthRecord reports whether auth represents a Codex credential record.
func IsCodexAuthRecord(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(auth.MetadataString("type")), "codex") {
		return true
	}
	if _, ok := auth.Storage.(*codex.CodexTokenStorage); ok {
		return true
	}
	return false
}

// PersistCodexAuthFile persists a Codex auth record to path using inter-process file locking,
// read-before-write merging, and scoped refresh patches when present.
// It returns handled=false when auth is not a Codex credential record.
func PersistCodexAuthFile(ctx context.Context, path string, auth *Auth) (bool, error) {
	if !IsCodexAuthRecord(auth) {
		return false, nil
	}

	type metadataSetter interface {
		SetMetadata(map[string]any)
	}

	// Persist from a private deep snapshot; publish it only after the write succeeds.
	metadata := codexMetadataSnapshot(auth)
	switch {
	case auth.CodexRefreshPatch != nil:
		var published map[string]any
		errRefresh := codex.WithFileLock(path, func() error {
			existing, errRead := os.ReadFile(path)
			if errRead != nil {
				if os.IsNotExist(errRead) {
					if metadata == nil {
						metadata = make(map[string]any)
					}
					metadata["disabled"] = auth.Disabled
					NormalizeCredentialMetadata(metadata)
					if errWrite := codex.WriteJSONFileAtomic(path, metadata); errWrite != nil {
						return errWrite
					}
					published = metadata
					return nil
				}
				return fmt.Errorf("auth filestore: read refresh source failed: %w", errRead)
			}
			var diskMap map[string]any
			if errUnmarshal := json.Unmarshal(existing, &diskMap); errUnmarshal != nil || diskMap == nil {
				return fmt.Errorf("auth filestore: invalid refresh source JSON")
			}
			merged := auth.CodexRefreshPatch.Apply(diskMap)
			NormalizeCredentialMetadata(merged)
			if errWrite := codex.WriteJSONFileAtomic(path, merged); errWrite != nil {
				return errWrite
			}
			published = merged
			return nil
		})
		if errRefresh != nil {
			return true, errRefresh
		}
		publishCodexMetadata(auth, published)
		auth.CodexRefreshPatch = nil
		auth.Storage = nil
		if disabled, ok := published["disabled"].(bool); ok {
			auth.Disabled = disabled
		}
		return true, nil

	case auth.Storage != nil:
		if metadata == nil {
			metadata = make(map[string]any)
		}
		metadata["disabled"] = auth.Disabled
		if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && storage != nil {
			clonedStorage := *storage
			clonedStorage.ReplaceCredentials = HasAuthCreationIntent(ctx)
			auth.Storage = &clonedStorage
		}
		if setter, ok := auth.Storage.(metadataSetter); ok {
			setter.SetMetadata(metadata)
		}
		if errSave := auth.Storage.SaveTokenToFile(path); errSave != nil {
			return true, errSave
		}
		if persistedBytes, errReadPersisted := os.ReadFile(path); errReadPersisted == nil && len(persistedBytes) > 0 {
			var diskMap map[string]any
			if errUnmarshal := json.Unmarshal(persistedBytes, &diskMap); errUnmarshal == nil && len(diskMap) > 0 {
				metadata = codex.MergeCodexCredentialsFromDisk(diskMap, metadata)
				NormalizeCredentialMetadata(metadata)
			}
		}
		publishCodexMetadata(auth, metadata)
		return true, nil

	case metadata != nil:
		metadata["disabled"] = auth.Disabled
		errLock := codex.WithFileLock(path, func() error {
			existing, errRead := os.ReadFile(path)
			if errRead == nil && len(existing) > 0 {
				var diskMap map[string]any
				if errUnmarshal := json.Unmarshal(existing, &diskMap); errUnmarshal == nil && len(diskMap) > 0 {
					if !HasAuthCreationIntent(ctx) {
						metadata = codex.MergeCodexCredentialsFromDisk(diskMap, metadata)
					}
					metadata["disabled"] = auth.Disabled
					NormalizeCredentialMetadata(metadata)
					if raw, errMarshal := json.Marshal(metadata); errMarshal == nil && string(existing) == string(raw) {
						return nil
					}
				}
			} else if errRead != nil && !os.IsNotExist(errRead) {
				return fmt.Errorf("auth filestore: read existing failed: %w", errRead)
			}
			return codex.WriteJSONFileAtomic(path, metadata)
		})
		if errLock != nil {
			return true, errLock
		}
		publishCodexMetadata(auth, metadata)
		return true, nil

	default:
		return false, nil
	}
}

// codexMetadataSnapshot deep-copies metadata under the credential's lock so
// persistence can merge and normalize without mutating the published map.
func codexMetadataSnapshot(auth *Auth) map[string]any {
	auth.metadataMu.RLock()
	defer auth.metadataMu.RUnlock()
	return cloneMetadataMap(auth.Metadata)
}

// publishCodexMetadata replaces the caller's metadata with the persisted map under
// the credential's lock. Callers must not mutate the map after publishing it.
func publishCodexMetadata(auth *Auth, metadata map[string]any) {
	auth.metadataMu.Lock()
	auth.Metadata = metadata
	auth.metadataMu.Unlock()
}
