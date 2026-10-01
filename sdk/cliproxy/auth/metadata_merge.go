package auth

import (
	"reflect"
	"strings"
	"time"
)

// IsAuthTokenPayloadKey returns true if key is a credential or token lifecycle field
// that should not overwrite newly acquired OAuth credentials during metadata merge.
func IsAuthTokenPayloadKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "access_token", "refresh_token", "id_token", "session_id",
		"expired", "last_refresh", "expires_in", "timestamp",
		"token_type", "user_code", "verification_uri", "verification_uri_complete":
		return true
	default:
		return false
	}
}

// MergeExistingAuthMetadata merges user-configured metadata fields from existingMap
// into target.Metadata and target.Storage if target does not already define them.
func MergeExistingAuthMetadata(target *Auth, existingMap map[string]any) {
	if target == nil || len(existingMap) == 0 {
		return
	}
	if target.Metadata == nil {
		target.Metadata = make(map[string]any)
	}
	if _, explicitlySet := target.Metadata["disabled"]; !explicitlySet {
		if disabled, ok := existingMap["disabled"].(bool); ok {
			target.Disabled = disabled
		}
	}
	for k, v := range existingMap {
		if IsAuthTokenPayloadKey(k) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(target.Provider), "meta") {
			switch CanonicalCredentialMetadataKey(k) {
			case "api_key", "dca_token", "dca_expired", "dca_expires_at":
				continue
			}
		}
		if _, exists := target.Metadata[k]; !exists {
			target.Metadata[k] = v
		}
	}
	if setter, ok := target.Storage.(interface{ SetMetadata(map[string]any) }); ok {
		setter.SetMetadata(target.Metadata)
	}
}

// MergePreparedAuth merges prepared request auth updates into current without modifying
// refresh lifecycle fields (such as LastRefreshedAt, LastError, or cooldown status).
func MergePreparedAuth(base, current, updated *Auth) *Auth {
	return mergeAuthContent(base, current, updated)
}

// MergeRefreshedAuth merges the refresh results from updated (derived from base)
// into the latest runtime auth current, preserving concurrent user modifications
// and active cooldowns.
func MergeRefreshedAuth(base, current, updated *Auth) *Auth {
	if base != nil && current != nil && authCredentialBindingChanged(base, current) {
		return current.Clone()
	}
	merged := mergeAuthContent(base, current, updated)
	if merged == nil || current == nil || updated == nil {
		return merged
	}
	if base != nil && current.RegistrationEpoch != base.RegistrationEpoch {
		return merged
	}

	// 1. Refresh Lifecycle Timestamps
	if !updated.LastRefreshedAt.IsZero() {
		merged.LastRefreshedAt = updated.LastRefreshedAt
	}
	if !updated.NextRefreshAfter.IsZero() || (base != nil && !base.NextRefreshAfter.IsZero()) {
		merged.NextRefreshAfter = updated.NextRefreshAfter
	}

	// 2. Error and Status recovery
	baseErrMsg := ""
	if base != nil && base.LastError != nil {
		baseErrMsg = base.LastError.Message
	}
	currentErrMsg := ""
	if current.LastError != nil {
		currentErrMsg = current.LastError.Message
	}
	hasNewConcurrentError := currentErrMsg != "" && currentErrMsg != baseErrMsg

	// 2. Disabled status three-way merge
	baseDisabled := base != nil && (base.Disabled || base.Status == StatusDisabled)
	currentDisabled := current.Disabled || current.Status == StatusDisabled
	updatedDisabled := updated.Disabled || updated.Status == StatusDisabled

	disabledChangedByExecutor := updatedDisabled != baseDisabled
	disabledChangedByUser := currentDisabled != baseDisabled

	finalDisabled := currentDisabled
	if disabledChangedByExecutor && !disabledChangedByUser {
		finalDisabled = updatedDisabled
	}

	if finalDisabled {
		merged.Disabled = true
		merged.Status = StatusDisabled
		merged.Metadata["disabled"] = true
	} else {
		merged.Disabled = false
		if merged.Status == StatusDisabled {
			merged.Status = StatusActive
		}
		merged.Metadata["disabled"] = false

		if hasNewConcurrentError {
			// A new error occurred concurrently (e.g. 503, 429, timeout). Preserve it.
			merged.LastError = current.LastError
			merged.Status = current.Status
			merged.Unavailable = current.Unavailable
			merged.StatusMessage = current.StatusMessage
		} else if current.Quota.Exceeded && current.Quota.Reason == "credential_quota" && current.Quota.NextRecoverAt.After(time.Now()) {
			// Preserve active credential quota
			merged.Unavailable = current.Unavailable
			merged.Status = current.Status
			merged.StatusMessage = current.StatusMessage
		} else if current.Unavailable && current.NextRetryAfter.After(time.Now()) {
			// Preserve active cooldown
			merged.Unavailable = current.Unavailable
			merged.Status = current.Status
			merged.StatusMessage = current.StatusMessage
		} else if updated.Status == StatusActive || updated.Status == "" {
			// Successful refresh clears previous auth error and restores active
			merged.Status = StatusActive
			merged.Unavailable = false
			merged.StatusMessage = ""
			merged.LastError = nil
		}
	}

	// 3. ModelStates: three-way merge to preserve concurrent cooldown/quota
	var baseModels map[string]*ModelState
	if base != nil {
		baseModels = base.ModelStates
	}
	if updated.ModelStates != nil {
		if merged.ModelStates == nil {
			merged.ModelStates = make(map[string]*ModelState)
		}
		for model, updState := range updated.ModelStates {
			baseState := baseModels[model]
			currentState := current.ModelStates[model]

			changedByExecutor := !reflect.DeepEqual(baseState, updState)
			changedByUser := !reflect.DeepEqual(baseState, currentState)

			if changedByExecutor && !changedByUser {
				merged.ModelStates[model] = updState
			}
		}
		if baseModels != nil {
			for model, baseState := range baseModels {
				if _, inUpdated := updated.ModelStates[model]; !inUpdated {
					if currentState, ok := current.ModelStates[model]; ok {
						if reflect.DeepEqual(baseState, currentState) {
							delete(merged.ModelStates, model)
						}
					}
				}
			}
		}
	}

	return merged
}

// authCredentialBindingChanged compares the token/identity unit, not unrelated
// user configuration or runtime health. It also protects direct merge callers.
func authCredentialBindingChanged(base, current *Auth) bool {
	if base == nil || current == nil {
		return false
	}
	if CredentialsChanged(base, current) || authCredentialIdentityChanged(base, current) {
		return true
	}
	for _, key := range []string{"api_key", "dca_token"} {
		if !reflect.DeepEqual(base.Metadata[key], current.Metadata[key]) || base.Attributes[key] != current.Attributes[key] {
			return true
		}
	}
	return false
}

func authCredentialIdentityChanged(base, current *Auth) bool {
	if base == nil || current == nil {
		return false
	}
	if base.Provider != current.Provider || base.FileName != current.FileName {
		return true
	}
	for _, key := range []string{"email", "account_id", "account_uuid", "organization_uuid"} {
		if !reflect.DeepEqual(base.Metadata[key], current.Metadata[key]) || base.Attributes[key] != current.Attributes[key] {
			return true
		}
	}
	return false
}

func isAuthCredentialBindingKey(key string) bool {
	key = CanonicalCredentialMetadataKey(key)
	if IsAuthTokenPayloadKey(key) {
		return true
	}
	switch key {
	case "email", "account_id", "account_uuid", "organization_uuid", "api_key", "dca_token":
		return true
	default:
		return false
	}
}

func mergeAuthContent(base, current, updated *Auth) *Auth {
	if current == nil {
		if updated != nil {
			return updated.Clone()
		}
		if base != nil {
			return base.Clone()
		}
		return nil
	}
	if updated == nil {
		return current.Clone()
	}
	if base != nil && (current.RegistrationEpoch != base.RegistrationEpoch || authCredentialIdentityChanged(base, current)) {
		// Stale update from a previous credential lifetime; keep current state.
		return current.Clone()
	}

	merged := current.Clone()
	bindingChanged := base != nil && authCredentialBindingChanged(base, current)
	if merged.Metadata == nil {
		merged.Metadata = make(map[string]any)
	}

	var baseMeta map[string]any
	if base != nil {
		baseMeta = base.Metadata
	}

	// 1. Three-way merge for Metadata (excluding proxy_url which has dedicated canonical merge)
	if updated.Metadata != nil {
		for k, v := range updated.Metadata {
			if bindingChanged && isAuthCredentialBindingKey(k) {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(k), "proxy_url") {
				continue
			}
			baseVal, hadInBase := baseMeta[k]
			currentVal, hadInCurrent := current.Metadata[k]

			changedByExecutor := !hadInBase || !reflect.DeepEqual(baseVal, v)
			changedByUser := hadInBase != hadInCurrent || (hadInBase && !reflect.DeepEqual(baseVal, currentVal))

			if changedByExecutor {
				// Never overwrite a newer token installed during preparation. Refresh
				// rejects a changed credential binding before entering this merge.
				if !changedByUser {
					merged.Metadata[k] = v
				}
			}
		}
		// Deletions by executor: only delete if user didn't modify the field concurrently
		if baseMeta != nil {
			for k, baseVal := range baseMeta {
				if bindingChanged && isAuthCredentialBindingKey(k) {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(k), "proxy_url") {
					continue
				}
				if _, inUpdated := updated.Metadata[k]; !inUpdated {
					if currentVal, ok := current.Metadata[k]; ok {
						if reflect.DeepEqual(baseVal, currentVal) {
							delete(merged.Metadata, k)
						}
					}
				}
			}
		}
	}

	// 2. Storage and Runtime
	if updated.Storage != nil && !bindingChanged {
		merged.Storage = updated.Storage
	}
	if updated.Runtime != nil && !bindingChanged {
		merged.Runtime = updated.Runtime
	}

	// 3. ProxyURL three-way merge (supporting both struct field and metadata modifications)
	baseStruct := ""
	if base != nil {
		baseStruct = strings.TrimSpace(base.ProxyURL)
	}
	currentStruct := strings.TrimSpace(current.ProxyURL)
	updatedStruct := strings.TrimSpace(updated.ProxyURL)

	baseMetaProxy := ""
	if base != nil && base.Metadata != nil {
		if s, ok := base.Metadata["proxy_url"].(string); ok {
			baseMetaProxy = strings.TrimSpace(s)
		}
	}
	currentMetaProxy := ""
	if current.Metadata != nil {
		if s, ok := current.Metadata["proxy_url"].(string); ok {
			currentMetaProxy = strings.TrimSpace(s)
		}
	}
	updatedMetaProxy := ""
	if updated.Metadata != nil {
		if s, ok := updated.Metadata["proxy_url"].(string); ok {
			updatedMetaProxy = strings.TrimSpace(s)
		}
	}

	userChangedStruct := currentStruct != baseStruct
	userChangedMeta := currentMetaProxy != baseMetaProxy
	execChangedStruct := updatedStruct != baseStruct
	execChangedMeta := updatedMetaProxy != baseMetaProxy

	finalProxy := currentStruct
	if currentMetaProxy != "" && currentStruct == "" && !userChangedStruct {
		finalProxy = currentMetaProxy
	}

	if userChangedStruct || userChangedMeta {
		// User modified proxy concurrently; user takes precedence over executor.
		if userChangedStruct && !userChangedMeta {
			finalProxy = currentStruct
		} else if userChangedMeta && !userChangedStruct {
			finalProxy = currentMetaProxy
		} else if currentStruct != "" {
			finalProxy = currentStruct
		} else {
			finalProxy = currentMetaProxy
		}
	} else if execChangedStruct || execChangedMeta {
		// Executor modified proxy and user did not touch it.
		if execChangedStruct && !execChangedMeta {
			finalProxy = updatedStruct
		} else if execChangedMeta && !execChangedStruct {
			finalProxy = updatedMetaProxy
		} else if updatedStruct != "" {
			finalProxy = updatedStruct
		} else {
			finalProxy = updatedMetaProxy
		}
	}

	if finalProxy != "" {
		merged.ProxyURL = finalProxy
		merged.Metadata["proxy_url"] = finalProxy
	} else {
		merged.ProxyURL = ""
		delete(merged.Metadata, "proxy_url")
	}

	// 4. Prefix (three-way merge, user modification takes precedence)
	basePrefix := ""
	if base != nil {
		basePrefix = strings.TrimSpace(base.Prefix)
	}
	currentPrefix := strings.TrimSpace(current.Prefix)
	updatedPrefix := strings.TrimSpace(updated.Prefix)

	if updatedPrefix != basePrefix && currentPrefix == basePrefix {
		merged.Prefix = updatedPrefix
	} else {
		merged.Prefix = currentPrefix
	}

	// 5. Attributes (three-way merge)
	if updated.Attributes != nil {
		if merged.Attributes == nil {
			merged.Attributes = make(map[string]string)
		}
		var baseAttrs map[string]string
		if base != nil {
			baseAttrs = base.Attributes
		}
		for k, v := range updated.Attributes {
			if bindingChanged && isAuthCredentialBindingKey(k) {
				continue
			}
			baseVal, hadInBase := baseAttrs[k]
			currentVal, hadInCurrent := current.Attributes[k]

			changedByExecutor := !hadInBase || baseVal != v
			changedByUser := hadInBase != hadInCurrent || (hadInBase && baseVal != currentVal)

			if changedByExecutor && !changedByUser {
				merged.Attributes[k] = v
			}
		}
		if baseAttrs != nil {
			for k, baseVal := range baseAttrs {
				if bindingChanged && isAuthCredentialBindingKey(k) {
					continue
				}
				if _, inUpdated := updated.Attributes[k]; !inUpdated {
					if currentVal, ok := current.Attributes[k]; ok {
						if baseVal == currentVal {
							delete(merged.Attributes, k)
						}
					}
				}
			}
		}
	}

	if !bindingChanged {
		syncCredentialEmailMirror(base, updated, merged)
	}
	return merged
}

// syncCredentialEmailMirror rotates the file-loaded email mirror with the OAuth
// identity. Only an unchanged mirror is synchronized; an explicit contradictory
// executor identity is left intact so policy validation rejects it.
func syncCredentialEmailMirror(base, updated, merged *Auth) {
	if base == nil || updated == nil || merged == nil {
		return
	}
	baseEmail, _ := base.Metadata["email"].(string)
	baseAttribute := base.Attributes["email"]
	if baseAttribute != "" && baseAttribute != baseEmail {
		return
	}
	if updated.Metadata != nil && !reflect.DeepEqual(base.Metadata["email"], updated.Metadata["email"]) && updated.Attributes["email"] == baseAttribute {
		if merged.Attributes == nil {
			merged.Attributes = make(map[string]string)
		}
		if email, _ := merged.Metadata["email"].(string); email != "" {
			merged.Attributes["email"] = email
		} else {
			delete(merged.Attributes, "email")
		}
	} else if updated.Attributes != nil && updated.Attributes["email"] != baseAttribute && reflect.DeepEqual(base.Metadata["email"], updated.Metadata["email"]) {
		if email := merged.Attributes["email"]; email != "" {
			merged.Metadata["email"] = email
		} else {
			delete(merged.Metadata, "email")
		}
	}
}
