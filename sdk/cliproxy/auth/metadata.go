package auth

import "encoding/json"

// MetadataValue reads an entry under the credential's metadata lock. Nested values
// are immutable: callers must replace them through SetMetadata or WithMetadata.
func (a *Auth) MetadataValue(key string) (any, bool) {
	if a == nil {
		return nil, false
	}
	a.metadataMu.RLock()
	defer a.metadataMu.RUnlock()
	value, ok := a.Metadata[key]
	return value, ok
}

// MetadataString returns a string entry, or the empty string for other types.
func (a *Auth) MetadataString(key string) string {
	value, _ := a.MetadataValue(key)
	text, _ := value.(string)
	return text
}

// MetadataBool returns a bool entry, or false for other types.
func (a *Auth) MetadataBool(key string) bool {
	value, _ := a.MetadataValue(key)
	flag, _ := value.(bool)
	return flag
}

// SetMetadata replaces an entry, initializing the map when needed.
func (a *Auth) SetMetadata(key string, value any) {
	a.WithMetadata(func(metadata map[string]any) { metadata[key] = value })
}

// WithMetadata performs an atomic read-modify-write under the credential's lock.
// The callback must not retain the map or call metadata methods on the same Auth.
// A nil Auth or callback is a no-op. Nested values must be replaced, not mutated.
func (a *Auth) WithMetadata(update func(map[string]any)) {
	if a == nil || update == nil {
		return
	}
	a.metadataMu.Lock()
	defer a.metadataMu.Unlock()
	if a.Metadata == nil {
		a.Metadata = make(map[string]any)
	}
	update(a.Metadata)
}

// CloneMetadata returns an independent shallow map snapshot under the read lock.
// It preserves nil; nested values remain immutable and may be shared.
func (a *Auth) CloneMetadata() map[string]any {
	if a == nil {
		return nil
	}
	a.metadataMu.RLock()
	defer a.metadataMu.RUnlock()
	if a.Metadata == nil {
		return nil
	}
	metadata := make(map[string]any, len(a.Metadata))
	for key, value := range a.Metadata {
		metadata[key] = value
	}
	return metadata
}

// NormalizeAuthMetadata canonicalizes credential keys under the Auth-owned lock
// without initializing absent metadata (runtime-only credentials need no store).
func NormalizeAuthMetadata(a *Auth) {
	if a == nil {
		return
	}
	a.metadataMu.Lock()
	defer a.metadataMu.Unlock()
	NormalizeCredentialMetadata(a.Metadata)
}

// MarshalJSON snapshots mutable metadata rather than exposing it to the encoder.
// Other Auth fields still require their existing owner/manager synchronization.
func (a *Auth) MarshalJSON() ([]byte, error) {
	type authJSON Auth
	return json.Marshal((*authJSON)(a.Clone()))
}
