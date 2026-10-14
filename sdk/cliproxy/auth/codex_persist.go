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
	if strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") || strings.EqualFold(strings.TrimSpace(auth.MetadataString("type")), "codex") {
		return true
	}
	_, ok := auth.Storage.(*codex.CodexTokenStorage)
	return ok
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

	switch {
	case auth.CodexRefreshPatch != nil:
		var persisted map[string]any
		errRefresh := codex.WithFileLock(path, func() error {
			existing, errRead := os.ReadFile(path)
			if errRead != nil {
				if !os.IsNotExist(errRead) {
					return fmt.Errorf("auth filestore: read refresh source failed: %w", errRead)
				}
				// The source may have been deleted after the executor released its
				// file lock but before the manager committed the refresh result.
				return codex.ErrRefreshNotPersisted
			} else {
				var diskMap map[string]any
				if errUnmarshal := json.Unmarshal(existing, &diskMap); errUnmarshal != nil || diskMap == nil {
					return fmt.Errorf("auth filestore: invalid refresh source JSON")
				}
				persisted = auth.CodexRefreshPatch.Apply(diskMap)
			}
			NormalizeCredentialMetadata(persisted)
			return codex.WriteJSONFileAtomic(path, persisted)
		})
		if errRefresh != nil {
			return true, errRefresh
		}
		auth.ReplaceMetadata(persisted)
		auth.CodexRefreshPatch = nil
		auth.Storage = nil
		if disabled, ok := persisted["disabled"].(bool); ok {
			auth.Disabled = disabled
		}
		return true, nil

	case auth.Storage != nil:
		auth.SetMetadata("disabled", auth.Disabled)
		if storage, ok := auth.Storage.(*codex.CodexTokenStorage); ok && storage != nil {
			clonedStorage := *storage
			clonedStorage.ReplaceCredentials = HasAuthCreationIntent(ctx)
			auth.Storage = &clonedStorage
		}
		if setter, ok := auth.Storage.(metadataSetter); ok {
			setter.SetMetadata(auth.CloneMetadata())
		}
		if errSave := auth.Storage.SaveTokenToFile(path); errSave != nil {
			return true, errSave
		}
		if persistedBytes, errReadPersisted := os.ReadFile(path); errReadPersisted == nil && len(persistedBytes) > 0 {
			var diskMap map[string]any
			if errUnmarshal := json.Unmarshal(persistedBytes, &diskMap); errUnmarshal == nil && len(diskMap) > 0 {
				metadata := codex.MergeCodexCredentialsFromDisk(diskMap, auth.CloneMetadata())
				NormalizeCredentialMetadata(metadata)
				auth.ReplaceMetadata(metadata)
			}
		}
		return true, nil

	case auth.CloneMetadata() != nil:
		auth.SetMetadata("disabled", auth.Disabled)
		metadata := auth.CloneMetadata()
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
		auth.ReplaceMetadata(metadata)
		return true, nil

	default:
		return false, nil
	}
}
