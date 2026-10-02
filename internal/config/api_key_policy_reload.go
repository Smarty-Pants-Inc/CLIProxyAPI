package config

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
)

// APIKeyPolicyReloadState retains a removed key's policy (nil means unpolicied)
// or a warning marker. Active unwarned keys use the current config as history.
type APIKeyPolicyReloadState struct {
	Policy *APIKeyPolicy
	Warned bool
}

// PreserveAPIKeyPolicies freezes known clients until restart, including clients
// removed and later re-added. New keys may acquire policies on reload. Callers
// validate both the requested and effective configuration before publication.
func PreserveAPIKeyPolicies(previous, next *Config) *Config {
	if next == nil {
		return nil
	}
	out := next.CloneForRuntime()
	history := map[string]APIKeyPolicyReloadState{}
	if previous == nil {
		for digest, state := range out.PolicyReloadState {
			history[digest] = state
		}
	}
	if previous != nil {
		old := previous.CloneForRuntime()
		for digest, state := range old.PolicyReloadState {
			history[digest] = state
		}
		for _, key := range old.APIKeys {
			digest := APIKeyDigest(key)
			if _, known := history[digest]; !known {
				history[digest] = APIKeyPolicyReloadState{Policy: findKeyPolicy(old.APIKeyPolicies, digest)}
			}
		}
	}
	requested := out.APIKeyPolicies
	out.APIKeyPolicies = nil
	for _, key := range out.APIKeys {
		digest := APIKeyDigest(key)
		want := findKeyPolicy(requested, digest)
		state, known := history[digest]
		// Carry the warning marker through service -> manager -> server -> provider.
		state.Warned = state.Warned || (known && next.PolicyReloadState[digest].Warned)
		if !known {
			state.Policy = want
		} else if !reflect.DeepEqual(state.Policy, want) && !state.Warned {
			log.Warnf("client-key policy change for %s takes effect on restart", digest)
			state.Warned = true
		}
		history[digest] = state
		if state.Policy != nil && findKeyPolicy(out.APIKeyPolicies, digest) == nil {
			out.APIKeyPolicies = append(out.APIKeyPolicies, *state.Policy)
		}
	}
	// Internal SDK snapshots may omit APIKeys; public entry points reject orphan
	// policies. Keep those existing SDK-only snapshots unchanged.
	for _, p := range requested {
		if _, known := history[p.KeySHA256]; !known {
			out.APIKeyPolicies = append(out.APIKeyPolicies, p)
		}
	}
	// Active, unchanged keys are already represented by APIKeys/APIKeyPolicies.
	// Retain only removed keys and warning markers in process-local history.
	for _, key := range out.APIKeys {
		digest := APIKeyDigest(key)
		if state := history[digest]; !state.Warned {
			delete(history, digest)
		}
	}
	if len(history) == 0 {
		history = nil
	}
	out.PolicyReloadState = history
	if reflect.DeepEqual(out.APIKeyPolicies, next.APIKeyPolicies) && reflect.DeepEqual(out.PolicyReloadState, next.PolicyReloadState) {
		return next
	}
	return out
}

// RetainAPIKeyPolicyWarnings keeps warning markers even when unrelated settings
// make the effective reload invalid. Rejected new keys do not enter history.
func RetainAPIKeyPolicyWarnings(previous, effective *Config) *Config {
	if previous == nil {
		return nil
	}
	retained := previous.CloneForRuntime()
	if retained.PolicyReloadState == nil {
		retained.PolicyReloadState = map[string]APIKeyPolicyReloadState{}
	}
	for digest, state := range effective.PolicyReloadState {
		known := false
		for _, key := range previous.APIKeys {
			if APIKeyDigest(key) == digest {
				known = true
			}
		}
		if prior, ok := retained.PolicyReloadState[digest]; ok {
			prior.Warned = prior.Warned || state.Warned
			retained.PolicyReloadState[digest] = prior
		} else if known {
			retained.PolicyReloadState[digest] = state
		}
	}
	return retained.CloneForRuntime()
}

// APIKeyDigest uses the same normalized client identity as policy validation.
func APIKeyDigest(key string) string {
	b := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(b[:])
}

func findKeyPolicy(policies []APIKeyPolicy, digest string) *APIKeyPolicy {
	for i := range policies {
		if policies[i].KeySHA256 == digest {
			return &policies[i]
		}
	}
	return nil
}
