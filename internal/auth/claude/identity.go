package claude

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const (
	ClaudeDeviceIDsMetadataKey = "claude_device_ids"
	ClaudeDevicePoolSize       = 1
	claudeDeviceIDByteSize     = 32
)

// claudeDevicePoolMu only protects the legacy standalone-map helper. Shared
// credentials must use EnsureDeviceIDPoolFor and the Auth-owned metadata lock.
var claudeDevicePoolMu sync.Mutex

// GenerateDeviceIDPool creates the fixed-size device pool stored with a Claude credential.
func GenerateDeviceIDPool() ([]string, error) {
	deviceIDs := make([]string, 0, ClaudeDevicePoolSize)
	seen := make(map[string]struct{}, ClaudeDevicePoolSize)
	for len(deviceIDs) < ClaudeDevicePoolSize {
		deviceID, errDeviceID := generateDeviceID()
		if errDeviceID != nil {
			return nil, errDeviceID
		}
		if _, exists := seen[deviceID]; exists {
			continue
		}
		seen[deviceID] = struct{}{}
		deviceIDs = append(deviceIDs, deviceID)
	}
	return deviceIDs, nil
}

func generateDeviceID() (string, error) {
	data := make([]byte, claudeDeviceIDByteSize)
	if _, errRead := rand.Read(data); errRead != nil {
		return "", fmt.Errorf("generate Claude device ID: %w", errRead)
	}
	return hex.EncodeToString(data), nil
}

// NormalizeDeviceIDPool returns the first valid device ID in canonical form.
func NormalizeDeviceIDPool(raw any) []string {
	var values []string
	switch typed := raw.(type) {
	case []string:
		values = typed
	case []any:
		values = make([]string, 0, len(typed))
		for _, value := range typed {
			if text, ok := value.(string); ok {
				values = append(values, text)
			}
		}
	default:
		return nil
	}

	deviceIDs := make([]string, 0, min(len(values), ClaudeDevicePoolSize))
	seen := make(map[string]struct{}, ClaudeDevicePoolSize)
	for _, value := range values {
		deviceID := strings.ToLower(strings.TrimSpace(value))
		if !ValidDeviceID(deviceID) {
			continue
		}
		if _, exists := seen[deviceID]; exists {
			continue
		}
		seen[deviceID] = struct{}{}
		deviceIDs = append(deviceIDs, deviceID)
		if len(deviceIDs) == ClaudeDevicePoolSize {
			break
		}
	}
	return deviceIDs
}

// HasCanonicalDeviceIDPool reports whether raw stores exactly one valid device ID.
func HasCanonicalDeviceIDPool(raw any) bool {
	var values []string
	switch typed := raw.(type) {
	case []string:
		values = typed
	case []any:
		values = make([]string, 0, len(typed))
		for _, value := range typed {
			text, ok := value.(string)
			if !ok {
				return false
			}
			values = append(values, text)
		}
	default:
		return false
	}
	normalized := NormalizeDeviceIDPool(values)
	return len(values) == ClaudeDevicePoolSize && len(normalized) == ClaudeDevicePoolSize && values[0] == normalized[0]
}

// EnsureDeviceIDPool repairs or creates the single-device pool in credential metadata.
func EnsureDeviceIDPool(metadata map[string]any) ([]string, bool, error) {
	claudeDevicePoolMu.Lock()
	defer claudeDevicePoolMu.Unlock()

	return ensureDeviceIDPoolLocked(metadata)
}

// EnsureDeviceIDPoolFor initializes and repairs the pool under the Auth-owned lock.
func EnsureDeviceIDPoolFor(auth *coreauth.Auth) (deviceIDs []string, changed bool, err error) {
	if auth == nil {
		return nil, false, fmt.Errorf("ensure Claude device pool: auth is nil")
	}
	auth.WithMetadata(func(metadata map[string]any) {
		deviceIDs, changed, err = ensureDeviceIDPoolLocked(metadata)
	})
	return
}

// ReadDeviceIDPool returns a defensive copy of the stored immutable pool value.
func ReadDeviceIDPool(auth *coreauth.Auth) any {
	raw, _ := auth.MetadataValue(ClaudeDeviceIDsMetadataKey)
	switch stored := raw.(type) {
	case []string:
		return append([]string(nil), stored...)
	case []any:
		return append([]any(nil), stored...)
	default:
		return stored
	}
}

// StoreDeviceIDPool replaces the pool with a defensive copy under the Auth-owned lock.
func StoreDeviceIDPool(auth *coreauth.Auth, deviceIDs []string) {
	auth.SetMetadata(ClaudeDeviceIDsMetadataKey, append([]string(nil), deviceIDs...))
}

// ReadMetadataString reads an entry under the Auth-owned metadata lock.
func ReadMetadataString(auth *coreauth.Auth, key string) string {
	return auth.MetadataString(key)
}

// ReadMetadataBool reads an entry under the Auth-owned metadata lock.
func ReadMetadataBool(auth *coreauth.Auth, key string) bool {
	return auth.MetadataBool(key)
}

// StoreMetadataString skips empty optional fields, preserving previously resolved values.
func StoreMetadataString(auth *coreauth.Auth, key, value string) {
	if strings.TrimSpace(value) != "" {
		auth.SetMetadata(key, value)
	}
}

// StoreMetadataValue replaces an entry under the Auth-owned metadata lock.
func StoreMetadataValue(auth *coreauth.Auth, key string, value any) {
	auth.SetMetadata(key, value)
}

// EnsureMetadataMap initializes the map under the Auth-owned metadata lock.
func EnsureMetadataMap(auth *coreauth.Auth) {
	auth.WithMetadata(func(map[string]any) {})
}

// ensureDeviceIDPoolLocked requires the owning lock or an unshared standalone map.
func ensureDeviceIDPoolLocked(metadata map[string]any) ([]string, bool, error) {
	if metadata == nil {
		return nil, false, fmt.Errorf("ensure Claude device pool: metadata is nil")
	}
	rawDeviceIDs := metadata[ClaudeDeviceIDsMetadataKey]
	deviceIDs := NormalizeDeviceIDPool(rawDeviceIDs)
	changed := !HasCanonicalDeviceIDPool(rawDeviceIDs)
	seen := make(map[string]struct{}, ClaudeDevicePoolSize)
	for _, deviceID := range deviceIDs {
		seen[deviceID] = struct{}{}
	}
	for len(deviceIDs) < ClaudeDevicePoolSize {
		deviceID, errDeviceID := generateDeviceID()
		if errDeviceID != nil {
			return nil, false, errDeviceID
		}
		if _, exists := seen[deviceID]; exists {
			continue
		}
		seen[deviceID] = struct{}{}
		deviceIDs = append(deviceIDs, deviceID)
	}

	if changed {
		metadata[ClaudeDeviceIDsMetadataKey] = append([]string(nil), deviceIDs...)
	}
	return append([]string(nil), deviceIDs...), changed, nil
}

// SelectDeviceID returns the credential's sole device ID after validating the conversation session.
func SelectDeviceID(deviceIDs []string, sessionID string) (string, error) {
	deviceIDs = NormalizeDeviceIDPool(deviceIDs)
	if len(deviceIDs) != ClaudeDevicePoolSize {
		return "", fmt.Errorf("select Claude device ID: device pool has %d entries, want %d", len(deviceIDs), ClaudeDevicePoolSize)
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", fmt.Errorf("select Claude device ID: session ID is empty")
	}
	return deviceIDs[0], nil
}

// ValidDeviceID reports whether a value matches Claude Code's lowercase 64-hex device format.
func ValidDeviceID(value string) bool {
	if len(value) != claudeDeviceIDByteSize*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, errDecode := hex.DecodeString(value)
	return errDecode == nil && len(decoded) == claudeDeviceIDByteSize
}
