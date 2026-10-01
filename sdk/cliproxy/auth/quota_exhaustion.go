package auth

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// quotaExhaustedUtilization is the utilization at or above which a quota
// window is treated as exhausted. Selection skips an account while any of its
// 5-hour or weekly windows sits at or above this level and the window has not
// reset yet: trying it would only spend a request on an upstream 429.
const quotaExhaustedUtilization = 0.98

// quotaMaxResetHorizon bounds how far ahead a recorded reset may lie. Quota
// windows are at most weekly, so a reset beyond this horizon is bogus data and
// is treated as unknown: an out-of-range value never causes a skip.
const quotaMaxResetHorizon = 30 * 24 * time.Hour

// quotaMaxTimestamp is the largest raw unix value (milliseconds) accepted
// before conversion, so huge values cannot overflow int64.
const quotaMaxTimestamp = 1e15

// quotaUsage summarizes the last passive quota snapshot of one account.
type quotaUsage struct {
	// utilization is the highest utilization (0..1) across the account's
	// still-current 5-hour and weekly windows. It ranks accounts when every
	// candidate is exhausted.
	utilization float64
	// exhausted reports that a window is at or above
	// quotaExhaustedUtilization (or rejected) and its reset is still ahead.
	exhausted bool
}

// quotaUsageOf reads the Anthropic unified 5h/7d and Codex primary/secondary
// watermarks the gateway records per account in Quota.Signals.
//
// A window only counts as exhausted while its reset time is known and in the
// future; once the reset passes the account is eligible again even if no newer
// response has refreshed the snapshot. A window without a parseable reset is
// never treated as exhausted, so incomplete data cannot remove capacity.
func quotaUsageOf(auth *Auth, now time.Time) quotaUsage {
	var usage quotaUsage
	if auth == nil || len(auth.Quota.Signals) == 0 {
		return usage
	}
	signals := auth.Quota.Signals
	observedAt := auth.Quota.ObservedAt

	horizonBase := observedAt
	if horizonBase.IsZero() || horizonBase.After(now) {
		horizonBase = now
	}
	consider := func(utilization float64, rejected bool, resetAt time.Time, resetKnown bool) {
		if resetKnown && resetAt.After(horizonBase.Add(quotaMaxResetHorizon)) {
			resetKnown = false // out of range: never a skip
		}
		if resetKnown && !resetAt.After(now) {
			return // the window has reset; the recorded usage is stale
		}
		if rejected && utilization < 1 {
			utilization = 1
		}
		if utilization > usage.utilization {
			usage.utilization = utilization
		}
		if resetKnown && (rejected || utilization >= quotaExhaustedUtilization) {
			usage.exhausted = true
		}
	}

	// Anthropic: utilization is a 0..1 fraction; status "rejected" means the
	// window is closed; reset is a unix timestamp.
	for _, window := range []string{"5h", "7d"} {
		prefix := "Anthropic-Ratelimit-Unified-" + window + "-"
		rawUtil, hasUtil := quotaSignal(signals, prefix+"Utilization")
		rawStatus, hasStatus := quotaSignal(signals, prefix+"Status")
		if !hasUtil && !hasStatus {
			continue
		}
		utilization, _ := parseQuotaFloat(rawUtil)
		rejected := strings.EqualFold(strings.TrimSpace(rawStatus), "rejected")
		resetAt, resetKnown := parseQuotaTimestamp(quotaSignalValue(signals, prefix+"Reset"))
		consider(utilization, rejected, resetAt, resetKnown)
	}

	// Codex: used-percent is 0..100; primary is the 5-hour window, secondary
	// the weekly one. Reset is an absolute unix timestamp or seconds after the
	// observation.
	limitReached := strings.EqualFold(strings.TrimSpace(quotaSignalValue(signals, "X-Codex-Limit-Reached")), "true")
	type codexWindow struct {
		utilization float64
		resetAt     time.Time
		resetKnown  bool
	}
	windows := make([]codexWindow, 0, 2)
	for _, window := range []string{"Primary", "Secondary"} {
		prefix := "X-Codex-" + window + "-"
		rawUsed, hasUsed := quotaSignal(signals, prefix+"Used-Percent")
		if !hasUsed && !limitReached {
			continue
		}
		used, okUsed := parseQuotaFloat(rawUsed)
		if !okUsed && !limitReached {
			continue
		}
		resetAt, resetKnown := parseQuotaTimestamp(quotaSignalValue(signals, prefix+"Reset-At"))
		if !resetKnown && !observedAt.IsZero() {
			if seconds, okSeconds := parseQuotaFloat(quotaSignalValue(signals, prefix+"Reset-After-Seconds")); okSeconds && seconds <= quotaMaxResetHorizon.Seconds() {
				resetAt = observedAt.Add(time.Duration(seconds * float64(time.Second)))
				resetKnown = true
			}
		}
		if !resetKnown && !hasUsed {
			continue
		}
		windows = append(windows, codexWindow{utilization: used / 100, resetAt: resetAt, resetKnown: resetKnown})
	}
	// limit_reached is reported once for the whole rate-limit object, not per
	// window. It belongs only to the window that actually hit its limit, so the
	// skip expires with that window's reset: a window at or above the threshold
	// owns it. When no window is at the threshold the responsible one cannot be
	// identified, and the flag is tied to the earliest known reset (normally the
	// 5-hour window) so the account is reconsidered then instead of being held
	// until an unrelated weekly reset.
	rejectedWindow := -1
	anyAtLimit := false
	if limitReached {
		for _, window := range windows {
			if window.utilization >= quotaExhaustedUtilization {
				anyAtLimit = true
			}
		}
		if !anyAtLimit {
			for i, window := range windows {
				if window.resetKnown && (rejectedWindow < 0 || window.resetAt.Before(windows[rejectedWindow].resetAt)) {
					rejectedWindow = i
				}
			}
		}
	}
	for i, window := range windows {
		rejected := limitReached && (i == rejectedWindow || (anyAtLimit && window.utilization >= quotaExhaustedUtilization))
		consider(window.utilization, rejected, window.resetAt, window.resetKnown)
	}
	return usage
}

// quotaExhausted reports whether selection should skip auth right now.
// A snapshot older than quotaReprobeInterval no longer causes a skip, so an
// account that was topped up before its window reset is tried again.
func quotaExhausted(auth *Auth, now time.Time) bool {
	if auth != nil && !auth.Quota.ObservedAt.IsZero() && now.Sub(auth.Quota.ObservedAt) > quotaReprobeInterval {
		return false
	}
	return quotaUsageOf(auth, now).exhausted
}

// skipQuotaExhausted removes accounts whose quota window is exhausted. When
// that would leave no candidate it returns only the least-utilized account, so
// selection never runs out of candidates because of this filter. The input
// order is preserved and the input slice is returned unchanged when nothing is
// skipped.
func skipQuotaExhausted(auths []*Auth, now time.Time) []*Auth {
	if len(auths) == 0 {
		return auths
	}
	exhaustedAt := -1
	for i, candidate := range auths {
		if quotaExhausted(candidate, now) {
			exhaustedAt = i
			break
		}
	}
	if exhaustedAt < 0 {
		return auths
	}
	kept := make([]*Auth, 0, len(auths))
	kept = append(kept, auths[:exhaustedAt]...)
	for _, candidate := range auths[exhaustedAt+1:] {
		if !quotaExhausted(candidate, now) {
			kept = append(kept, candidate)
		}
	}
	if len(kept) > 0 {
		return kept
	}
	return []*Auth{leastUtilizedAuth(auths, now)}
}

// leastUtilizedAuth returns the candidate with the lowest utilization. Ties go
// to the higher priority, then the lower ID, so the choice is deterministic.
func leastUtilizedAuth(auths []*Auth, now time.Time) *Auth {
	var best *Auth
	bestUtil := math.Inf(1)
	for _, candidate := range auths {
		if candidate == nil {
			continue
		}
		util := quotaUsageOf(candidate, now).utilization
		if best == nil || util < bestUtil ||
			(util == bestUtil && (authPriority(candidate) > authPriority(best) ||
				(authPriority(candidate) == authPriority(best) && candidate.ID < best.ID))) {
			best = candidate
			bestUtil = util
		}
	}
	return best
}

// skipQuotaExhaustedBuckets applies skipQuotaExhausted across priority
// buckets, so an exhausted top tier falls through to a lower tier with
// headroom before the least-utilized fallback is used.
func skipQuotaExhaustedBuckets(buckets map[int][]*Auth, now time.Time) map[int][]*Auth {
	if len(buckets) == 0 {
		return buckets
	}
	var all []*Auth
	anyExhausted := false
	for _, bucket := range buckets {
		for _, candidate := range bucket {
			all = append(all, candidate)
			if !anyExhausted && quotaExhausted(candidate, now) {
				anyExhausted = true
			}
		}
	}
	if !anyExhausted {
		return buckets
	}
	filtered := make(map[int][]*Auth, len(buckets))
	for _, candidate := range skipQuotaExhausted(all, now) {
		priority := authPriority(candidate)
		filtered[priority] = append(filtered[priority], candidate)
	}
	return filtered
}

func quotaSignal(signals map[string]string, name string) (string, bool) {
	if value, ok := signals[name]; ok {
		return value, true
	}
	if value, ok := signals[http.CanonicalHeaderKey(name)]; ok {
		return value, true
	}
	for key, value := range signals {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func quotaSignalValue(signals map[string]string, name string) string {
	value, _ := quotaSignal(signals, name)
	return value
}

func parseQuotaFloat(raw string) (float64, bool) {
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "%"))
	if raw == "" {
		return 0, false
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0, false
	}
	return value, true
}

// parseQuotaTimestamp accepts unix seconds (or milliseconds) and RFC 3339.
func parseQuotaTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if value, ok := parseQuotaFloat(raw); ok {
		if value <= 0 || value >= quotaMaxTimestamp {
			return time.Time{}, false
		}
		if value > 1e12 {
			return time.UnixMilli(int64(value)), true
		}
		seconds := int64(value)
		return time.Unix(seconds, int64((value-float64(seconds))*1e9)), true
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	return time.Time{}, false
}
