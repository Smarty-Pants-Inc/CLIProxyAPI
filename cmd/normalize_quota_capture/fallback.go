package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const producerFallbackBasis = "fallback:auth-files+used_percent"

// Presence is independent of the SDK collector accepting a value. In particular,
// an empty or malformed explicit flag must not become a missing-flag fallback.
// The SDK rejects conflicting canonical spellings before any window is usable.
func producerHeaderValue(headers http.Header, key string) (string, bool) {
	for name, values := range headers {
		if http.CanonicalHeaderKey(strings.TrimSpace(name)) == key {
			if len(values) == 0 {
				return "", true
			}
			return strings.TrimSpace(values[len(values)-1]), true
		}
	}
	return "", false
}

// This predicate is deliberately separate from authFileCooldown: a model quota
// reason can veto the limit predicate without becoming a credential cooldown.
// Only exact native exporter reason codes can prove a known non-quota entry.
func authFileQuotaCooldown(raw json.RawMessage) *bool {
	var entries []json.RawMessage
	if errDecode := json.Unmarshal(raw, &entries); errDecode != nil || entries == nil {
		return nil
	}
	unknown := false
	for _, entry := range entries {
		var fields struct {
			Scope  json.RawMessage `json:"scope"`
			Reason json.RawMessage `json:"reason"`
		}
		if errDecode := json.Unmarshal(entry, &fields); errDecode != nil {
			unknown = true
			continue
		}
		var reason string
		if errDecode := json.Unmarshal(fields.Reason, &reason); errDecode != nil {
			unknown = true
			continue
		}
		switch reason {
		case "quota", "credential_quota":
			value := true
			return &value // A known quota reason vetoes even an unknown scope.
		case "cloudflare_challenge", "invalid_grant", "unauthorized", "payment_required", "not_found", "model_not_supported", "transient_error":
		default:
			unknown = true
			continue
		}
		var scope string
		if errDecode := json.Unmarshal(fields.Scope, &scope); errDecode != nil || (scope != "credential" && scope != "model") {
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	value := false
	return &value
}

// Fresh independent vetoes need not prove the complete safe-auth predicate.
// False from any missing-flag window does: typed active health, known absence of
// quota cooldown, and fresh used-percent evidence for every required window.
// Uncertain/catching-up quota is never consulted, including its hidden anchor.
func producerLimitReachedWithFallback(row captureSeat, quota auth.QuotaWindowsView, file *producerAuthFile, authAt time.Time, quotaSelected bool, now time.Time) (*bool, time.Time, []string, string) {
	authFresh := file != nil && file.Provider == "codex" && freshAcquisition(authAt, now)
	var quotaCooldown *bool
	authSafe := false
	if authFresh {
		active := authFileActive(*file)
		quotaCooldown = authFileQuotaCooldown(file.Cooldowns)
		authSafe = active != nil && *active && quotaCooldown != nil && !*quotaCooldown
	}
	var value *bool
	var at time.Time
	var keys []string
	var basis string
	if quotaSelected {
		value, at, keys, basis = producerLimitEvidence(row, quota, now, true, authSafe)
	}
	if value != nil && *value && basis == "" && authFresh {
		return value, at, keys, basis // Preserve explicit refusal precedence.
	}
	if quotaCooldown != nil && *quotaCooldown {
		limited := true
		return &limited, authAt, nil, producerFallbackBasis
	}
	if value != nil && (authFresh || (*value && basis == producerFallbackBasis)) {
		return value, at, keys, basis
	}
	return nil, time.Time{}, nil, ""
}
