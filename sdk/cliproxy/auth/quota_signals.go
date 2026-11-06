package auth

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	maxQuotaSignalHeaders = 64
	maxQuotaSignalValue   = 512
)

// ProviderSupportsQuotaObservation reports whether the named provider emits a
// passive credential-level quota snapshot understood by collectQuotaSignals.
func ProviderSupportsQuotaObservation(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude", "codex", "devin":
		return true
	default:
		return false
	}
}

// ObserveResponseHeadersForProvider replaces the passive quota snapshot with the
// signals carried by the current upstream response.
//
// The snapshot is replaced rather than merged: a watermark such as Retry-After
// or a "limit reached" flag only appears on the response that produced it, so
// accumulating signals across responses would leave an expired value visible
// indefinitely. Responses that carry no quota signal at all (transport
// failures, 5xx, unrelated endpoints) leave the previous snapshot untouched.
//
// This compatibility entry point treats observedAt as one acquisition for all
// headers. Cooldown and scheduling fields are never read or written here.
func (q *QuotaState) ObserveResponseHeadersForProvider(provider string, headers http.Header, observedAt time.Time) bool {
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	times := make(map[string]time.Time, len(headers))
	for key := range headers {
		times[http.CanonicalHeaderKey(strings.TrimSpace(key))] = observedAt
	}
	return q.ObserveResponseHeadersObservationForProvider(provider, headers, times)
}

// ObserveResponseHeadersObservationForProvider replaces a response snapshot with
// its matching per-signal acquisitions. Missing provenance stays unknown; it is
// never filled from completion time or the legacy scalar. Separate executions
// are not unioned, and an older acquisition cannot replace newer evidence.
func (q *QuotaState) ObserveResponseHeadersObservationForProvider(provider string, headers http.Header, signalObservedAt map[string]time.Time) bool {
	if q == nil {
		return false
	}
	if !ProviderSupportsQuotaObservation(provider) {
		return q.ClearObservationSignals()
	}
	next := QuotaState{Signals: collectQuotaSignals(provider, headers)}
	if len(next.Signals) == 0 {
		return false
	}
	unknown := false
	for key := range next.Signals {
		acquired := signalObservedAt[key]
		if acquired.IsZero() {
			unknown = true
			continue
		}
		if next.SignalObservedAt == nil {
			next.SignalObservedAt = make(map[string]time.Time, len(next.Signals))
		}
		next.SignalObservedAt[key] = acquired
		if next.ObservedAt.IsZero() || acquired.Before(next.ObservedAt) {
			next.ObservedAt = acquired
		}
	}
	if unknown {
		next.ObservedAt = time.Time{}
	}
	if !quotaObservationCanReplace(*q, next) {
		return false
	}
	q.Signals = next.Signals
	q.ObservedAt = next.ObservedAt
	q.SignalObservedAt = next.SignalObservedAt
	return true
}

// ClearObservationSignals removes only passive observation data. It leaves
// cooldown and scheduler state untouched.
func (q *QuotaState) ClearObservationSignals() bool {
	if q == nil || (len(q.Signals) == 0 && q.ObservedAt.IsZero() && len(q.SignalObservedAt) == 0) {
		return false
	}
	q.Signals = nil
	q.ObservedAt = time.Time{}
	q.SignalObservedAt = nil
	return true
}

// cooldownFieldsOf copies only scheduler cooldown fields. Observation data is
// omitted so cooldown persistence and restore cannot replace a live snapshot.
func cooldownFieldsOf(q QuotaState) QuotaState {
	return QuotaState{
		Exceeded:      q.Exceeded,
		Reason:        q.Reason,
		NextRecoverAt: q.NextRecoverAt,
		BackoffLevel:  q.BackoffLevel,
	}
}

// applyCooldownFields writes only scheduler cooldown fields. ObservedAt and
// Signals are left untouched so a cooldown transition cannot erase the last
// upstream watermark.
func applyCooldownFields(dst *QuotaState, cooldown QuotaState) {
	if dst == nil {
		return
	}
	dst.Exceeded = cooldown.Exceeded
	dst.Reason = cooldown.Reason
	dst.NextRecoverAt = cooldown.NextRecoverAt
	dst.BackoffLevel = cooldown.BackoffLevel
}

// collectQuotaSignals builds the bounded snapshot for a single response.
func collectQuotaSignals(provider string, headers http.Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	names := make([]string, 0, len(headers))
	values := make(map[string]string, len(headers))
	for key, headerValues := range headers {
		canonicalKey := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if !isQuotaSignalHeaderForProvider(provider, canonicalKey) || len(headerValues) == 0 {
			continue
		}
		value := strings.TrimSpace(headerValues[len(headerValues)-1])
		if !validQuotaSignalValue(value) {
			continue
		}
		if _, exists := values[canonicalKey]; !exists {
			names = append(names, canonicalKey)
		}
		values[canonicalKey] = value
	}
	if len(names) == 0 {
		return nil
	}
	// Rank then sort so truncation is deterministic and keeps credential-level
	// watermarks (plan, credits, primary) ahead of additional-limit namespaces.
	sort.Slice(names, func(i, j int) bool {
		ri, rj := quotaSignalRetentionRank(names[i]), quotaSignalRetentionRank(names[j])
		if ri != rj {
			return ri < rj
		}
		return names[i] < names[j]
	})
	if len(names) > maxQuotaSignalHeaders {
		names = names[:maxQuotaSignalHeaders]
	}
	signals := make(map[string]string, len(names))
	for _, name := range names {
		signals[name] = values[name]
	}
	return signals
}

// validQuotaSignalValue rejects empty, oversized, and control-character values.
// Observed values reach the plain-text upstream request log, so a value
// containing CR/LF could otherwise forge a header line there.
func validQuotaSignalValue(value string) bool {
	if value == "" || len(value) > maxQuotaSignalValue {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}

func quotaSignalRetentionRank(name string) int {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case lower == "retry-after", strings.HasPrefix(lower, "anthropic-ratelimit-unified-"):
		return 0
	case lower == "x-codex-plan-type", lower == "x-codex-active-limit", strings.HasPrefix(lower, "x-codex-credits-"):
		return 1
	case lower == "x-codex-allowed", lower == "x-codex-limit-reached",
		strings.HasPrefix(lower, "x-codex-primary-"), strings.HasPrefix(lower, "x-codex-secondary-"):
		return 2
	case strings.HasPrefix(lower, "x-codex-code-review-"):
		return 3
	case strings.HasPrefix(lower, "x-codex-additional-"):
		return 5
	case strings.HasPrefix(lower, "x-codex-"):
		return 4
	default:
		return 6
	}
}

func isQuotaSignalHeaderForProvider(provider, name string) bool {
	provider = strings.ToLower(strings.TrimSpace(provider))
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "retry-after" {
		return provider == "claude" || provider == "codex"
	}
	if strings.HasPrefix(name, "anthropic-ratelimit-unified-") {
		return provider == "claude"
	}
	if strings.HasPrefix(name, "x-ratelimit-") {
		// Observed Codex responses do not carry x-ratelimit-* headers; the only
		// upstream seen emitting them is Grok, which is excluded from quota
		// observation. The rule is kept so a future Codex rollout is captured
		// without another change, but it is expected to be inert today.
		return provider == "codex"
	}
	if !strings.HasPrefix(name, "x-codex-") {
		return false
	}
	if provider != "codex" {
		return false
	}
	if name == "x-codex-active-limit" || name == "x-codex-plan-type" ||
		strings.HasPrefix(name, "x-codex-credits-") {
		return true
	}
	// Codex namespaces each additional limit by a short name on the HTTP path
	// (x-codex-bengalfox-primary-used-percent) and by limit name on the
	// websocket path (x-codex-additional-<limit>-primary-used-percent), so the
	// suffix is matched instead of an exhaustive header list.
	for _, marker := range []string{
		"-allowed",
		"-limit-reached",
		"-limit-name",
		"-used-percent",
		"-window-minutes",
		"-reset-after-seconds",
		"-reset-at",
		"-over-secondary-limit-percent",
	} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

// mergeQuotaObservation keeps the newest observation snapshot instead of
// unioning signals captured at different times, so merging an older snapshot
// can never resurrect a stale watermark.
func mergeQuotaObservation(target, source QuotaState) QuotaState {
	if !quotaObservationCanReplace(target, source) {
		return target
	}
	observation := source.Clone()
	target.ObservedAt = observation.ObservedAt
	target.Signals = observation.Signals
	target.SignalObservedAt = observation.SignalObservedAt
	return target
}

func newestQuotaAcquisition(q QuotaState) time.Time {
	var newest time.Time
	for key := range q.Signals {
		if acquired := q.SignalObservedAt[key]; acquired.After(newest) {
			newest = acquired
		}
	}
	if newest.IsZero() {
		// Legacy ordering compatibility only; do not manufacture per-signal
		// verification from this potentially completion-stamped scalar.
		return q.ObservedAt
	}
	return newest
}

func quotaObservationCanReplace(target, source QuotaState) bool {
	if len(source.Signals) == 0 || newestQuotaAcquisition(source).Before(newestQuotaAcquisition(target)) {
		return false
	}
	// Mixed acquisitions can be incomparable. Keep the current whole response
	// rather than regressing a retained signal or unioning different attempts.
	for key := range source.Signals {
		if _, exists := target.Signals[key]; exists {
			if source.SignalObservedAt[key].Before(target.SignalObservedAt[key]) {
				return false
			}
		}
	}
	return true
}
