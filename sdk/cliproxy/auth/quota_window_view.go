package auth

import (
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// QuotaWindowProvenance labels the caller's observation source. TimestampBasis
// describes legacy ObservedAt only; it cannot verify acquisition without the
// matching per-header QuotaState.SignalObservedAt entries.
type QuotaWindowProvenance struct {
	Source         string `json:"source"`
	TimestampBasis string `json:"timestamp_basis"`
}

// QuotaWindowDiagnostic retains reset evidence without implying current capacity.
// ResetDeltaSeconds is absolute reset minus the relative reset's implied time.
type QuotaWindowDiagnostic struct {
	Code                 string   `json:"code"`
	RelativeResetSeconds *float64 `json:"relative_reset_seconds,omitempty"`
	ImpliedResetAt       *float64 `json:"implied_reset_at,omitempty"`
	ResetDeltaSeconds    *float64 `json:"reset_delta_seconds,omitempty"`
}

// QuotaWindowView is measured evidence, not routing or spending permission.
// LimitKey is an opaque provider namespace, not a model. All times are UTC Unix
// seconds; percentages are 0..100. Required nullable numbers distinguish unknown
// from measured zero. UpstreamWindow is a source slot, never a duration claim.
type QuotaWindowView struct {
	LimitKey        string                  `json:"limit_key"`
	UpstreamWindow  string                  `json:"upstream_window"`
	DurationSeconds *int64                  `json:"duration_seconds"`
	UsedPercent     *float64                `json:"used_percent"`
	HeadroomPercent *float64                `json:"headroom_percent"`
	ResetAt         *float64                `json:"reset_at"`
	ObservedAt      *float64                `json:"observed_at"`
	AgeSeconds      *float64                `json:"age_seconds"`
	Source          string                  `json:"source"`
	TimestampBasis  string                  `json:"timestamp_basis"`
	State           string                  `json:"state"`
	Reason          string                  `json:"reason,omitempty"`
	Diagnostics     []QuotaWindowDiagnostic `json:"diagnostics,omitempty"`
}

// QuotaCreditFacts records provider facts only. No field authorizes purchasing
// credits, clears included-quota exhaustion, or approves overage spending.
type QuotaCreditFacts struct {
	HasCredits            *bool    `json:"has_credits"`
	Unlimited             *bool    `json:"unlimited"`
	Balance               *float64 `json:"balance"`
	CanPurchase           *bool    `json:"can_purchase"`
	HasPaymentMethod      *bool    `json:"has_payment_method"`
	ExhaustedIncluded     *bool    `json:"exhausted_included"`
	OverageStatus         string   `json:"overage_status,omitempty"`
	OverageDisabledReason string   `json:"overage_disabled_reason,omitempty"`
}

// QuotaWindowsView summarizes evidence only. Aggregate LimitSignals are not
// attributed to individual windows or models. Identity, health, cooldowns and
// spending approval belong to the caller's envelope and remain independent.
type QuotaWindowsView struct {
	State        string            `json:"state"`
	Reason       string            `json:"reason,omitempty"`
	Windows      []QuotaWindowView `json:"windows"`
	Plan         string            `json:"plan,omitempty"`
	ActiveLimit  string            `json:"active_limit,omitempty"`
	Credits      QuotaCreditFacts  `json:"credits"`
	LimitSignals map[string]string `json:"limit_signals,omitempty"`
}

var quotaWindowDecimal = regexp.MustCompile(`^(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)$`)

// NormalizeQuotaHeaderWindows adapts captured header arrays without inventing
// acquisition times. acquiredAt contains caller-supplied upstream acquisition
// times by header name, not request, insert, replay or capture times. Nil times
// preserve numeric facts but cannot produce known current headroom.
func NormalizeQuotaHeaderWindows(provider string, headers http.Header, acquiredAt map[string]time.Time, now time.Time, provenance QuotaWindowProvenance) QuotaWindowsView {
	if quotaWindowConflictingHeaders(provider, headers, acquiredAt) {
		return QuotaWindowsView{State: "unknown", Reason: "conflicting_header_evidence", Windows: make([]QuotaWindowView, 0)}
	}
	signals := collectQuotaSignals(provider, headers)
	observation := QuotaState{Signals: signals}
	keys := make([]string, 0, len(acquiredAt))
	for key := range acquiredAt {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if _, exists := signals[canonical]; !exists {
			continue
		}
		if observation.SignalObservedAt == nil {
			observation.SignalObservedAt = make(map[string]time.Time)
		}
		observation.SignalObservedAt[canonical] = acquiredAt[key]
	}
	return NormalizeQuotaWindows(provider, observation, now, provenance)
}

// NormalizeQuotaWindows projects a detached, bounded Claude/Codex observation.
// It performs no I/O, reads no clock/configuration, and changes no native quota
// or selector behavior. Freshness is fixed at <=300 seconds and requires a
// coherent acquisition timestamp for every present field of a window. A legacy
// scalar ObservedAt is retained as evidence, never upgraded to acquisition time.
func NormalizeQuotaWindows(provider string, observation QuotaState, now time.Time, provenance QuotaWindowProvenance) QuotaWindowsView {
	view := QuotaWindowsView{State: "unknown", Windows: make([]QuotaWindowView, 0)}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "claude" && provider != "codex" {
		view.Reason = "unsupported_provider"
		return view
	}
	// Preserve spellings until conflicting canonical names have been rejected;
	// sorting and overwriting would turn ambiguous evidence into a known fact.
	headers := make(http.Header, len(observation.Signals))
	for key, value := range observation.Signals {
		headers[key] = []string{value}
	}
	if quotaWindowConflictingHeaders(provider, headers, observation.SignalObservedAt) {
		view.Reason = "conflicting_header_evidence"
		return view
	}
	// Reuse native allowlisting/value/count bounds after the ambiguity check.
	signals := collectQuotaSignals(provider, headers)
	if len(signals) == 0 {
		view.Reason = "not_observed"
		return view
	}
	if provenance.Source == "" {
		provenance.Source = "unknown"
	}
	view.LimitSignals = quotaWindowLimitSignals(provider, signals)
	if provider == "claude" {
		view.Credits.CanPurchase = quotaWindowBool(signals, "Anthropic-Ratelimit-Unified-Credits-Can-Purchase")
		view.Credits.HasPaymentMethod = quotaWindowBool(signals, "Anthropic-Ratelimit-Unified-Credits-Has-Payment-Method")
		view.Credits.ExhaustedIncluded = quotaWindowBool(signals, "Anthropic-Ratelimit-Unified-Credits-Exhausted-Included")
		view.Credits.OverageStatus = quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Overage-Status")
		view.Credits.OverageDisabledReason = quotaSignalValue(signals, "Anthropic-Ratelimit-Unified-Overage-Disabled-Reason")
		for _, slot := range []string{"5h", "7d", "7d_oi"} {
			prefix := "Anthropic-Ratelimit-Unified-" + slot + "-"
			if slot == "7d_oi" && !quotaWindowHasPrefix(signals, prefix) {
				continue
			}
			view.Windows = append(view.Windows, normalizeQuotaWindow(signals, observation, now, provenance, "unified", slot, prefix, true))
		}
	} else {
		view.Plan = quotaSignalValue(signals, "X-Codex-Plan-Type")
		view.ActiveLimit = quotaSignalValue(signals, "X-Codex-Active-Limit")
		view.Credits.HasCredits = quotaWindowBool(signals, "X-Codex-Credits-Has-Credits")
		view.Credits.Unlimited = quotaWindowBool(signals, "X-Codex-Credits-Unlimited")
		if balance, ok := quotaWindowFloat(quotaSignalValue(signals, "X-Codex-Credits-Balance"), math.MaxFloat64); ok {
			view.Credits.Balance = &balance
		}
		for _, prefix := range quotaWindowCodexPrefixes(signals) {
			for _, slot := range []string{"primary", "secondary"} {
				view.Windows = append(view.Windows, normalizeQuotaWindow(signals, observation, now, provenance, strings.TrimSuffix(strings.ToLower(prefix), "-"), slot, prefix+slot+"-", false))
			}
		}
	}
	sort.Slice(view.Windows, func(i, j int) bool {
		a, b := view.Windows[i], view.Windows[j]
		if a.LimitKey != b.LimitKey {
			return a.LimitKey < b.LimitKey
		}
		if a.DurationSeconds == nil || b.DurationSeconds == nil {
			if (a.DurationSeconds == nil) != (b.DurationSeconds == nil) {
				return b.DurationSeconds == nil
			}
		} else if *a.DurationSeconds != *b.DurationSeconds {
			return *a.DurationSeconds < *b.DurationSeconds
		}
		return a.UpstreamWindow < b.UpstreamWindow
	})
	view.State = quotaWindowsState(view.Windows)
	if view.State == "unknown" {
		view.Reason = "metadata_only"
		for _, window := range view.Windows {
			if window.Reason != "not_observed" {
				view.Reason = "incomplete_window_evidence"
				break
			}
		}
	}
	return view
}

// Reject conflicting canonical names before the native collector loses their
// spelling. Earlier array entries are not evidence: native collection uses only
// the trimmed last value. Identical values and acquisition instants may agree.
func quotaWindowConflictingHeaders(provider string, headers http.Header, acquiredAt map[string]time.Time) bool {
	values := make(map[string]string, len(headers))
	for key, entries := range headers {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if !isQuotaSignalHeaderForProvider(provider, canonical) || len(entries) == 0 {
			continue
		}
		value := strings.TrimSpace(entries[len(entries)-1])
		if previous, exists := values[canonical]; exists && previous != value {
			return true
		}
		values[canonical] = value
	}
	times := make(map[string]time.Time, len(acquiredAt))
	for key, at := range acquiredAt {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(key))
		if _, exists := values[canonical]; !exists {
			continue
		}
		if previous, exists := times[canonical]; exists && !previous.Equal(at) {
			return true
		}
		times[canonical] = at
	}
	return false
}

func normalizeQuotaWindow(signals map[string]string, observation QuotaState, now time.Time, provenance QuotaWindowProvenance, limitKey, slot, prefix string, claude bool) QuotaWindowView {
	w := QuotaWindowView{LimitKey: limitKey, UpstreamWindow: slot, Source: provenance.Source, State: "unknown"}
	usedKey, absoluteKey := prefix+"Used-Percent", prefix+"Reset-At"
	fields := []string{usedKey, prefix + "Window-Minutes", absoluteKey, prefix + "Reset-After-Seconds", prefix + "Allowed", prefix + "Limit-Reached"}
	maximum := 100.0
	if claude {
		usedKey, absoluteKey = prefix+"Utilization", prefix+"Reset"
		fields = []string{usedKey, absoluteKey, prefix + "Status"}
		maximum = 1
		duration := int64(604800)
		if slot == "5h" {
			duration = 18000
		}
		w.DurationSeconds = &duration
		if slot == "7d_oi" {
			w.LimitKey = "7d_oi"
		}
	}
	observed, verified, timingReason := quotaWindowObservation(&w, signals, observation, fields, now, provenance)
	if !quotaWindowHasPrefix(signals, prefix) {
		w.Reason = "not_observed"
		return w
	}
	if !claude {
		raw, exists := quotaSignal(signals, prefix+"Window-Minutes")
		if !exists {
			w.Reason = "missing_duration"
		} else if minutes, ok := quotaWindowMinutes(raw); !ok {
			w.Reason = "invalid_duration"
		} else if minutes == 0 {
			// Only the explicit duration is evidence of absence. Other fields
			// often contain sentinel zeros and do not describe free capacity.
			_, _, absenceTiming := quotaWindowObservation(&w, signals, observation, []string{prefix + "Window-Minutes"}, now, provenance)
			w.State, w.Reason = "not_applicable", "upstream_absent"
			if absenceTiming != "" {
				w.State, w.Reason = quotaWindowTimingState(absenceTiming), absenceTiming
			}
			return w
		} else {
			duration := minutes * 60
			w.DurationSeconds = &duration
		}
	}
	if raw, exists := quotaSignal(signals, usedKey); exists {
		if used, ok := quotaWindowFloat(raw, maximum); ok {
			if claude {
				used *= 100
			}
			headroom := 100 - used
			w.UsedPercent, w.HeadroomPercent = &used, &headroom
		} else if w.Reason == "" {
			w.Reason = "invalid_utilization"
		}
	}
	rejected := false
	if claude {
		if raw, exists := quotaSignal(signals, prefix+"Status"); exists {
			switch strings.ToLower(raw) {
			case "rejected":
				rejected = true
			case "allowed":
			default:
				if w.Reason == "" {
					w.Reason = "invalid_window_status"
				}
			}
		}
	} else {
		for _, suffix := range []string{"Allowed", "Limit-Reached"} {
			if _, exists := quotaSignal(signals, prefix+suffix); !exists {
				continue
			}
			value := quotaWindowBool(signals, prefix+suffix)
			if value == nil {
				if w.Reason == "" {
					w.Reason = "invalid_window_status"
				}
			} else if (suffix == "Allowed" && !*value) || (suffix == "Limit-Reached" && *value) {
				rejected = true
			}
		}
	}
	resetAt, resetReason := quotaWindowReset(&w, signals, observation, absoluteKey, prefix+"Reset-After-Seconds", observed, verified, now, claude)
	if w.Reason == "" {
		w.Reason = resetReason
	}
	if w.Reason == "" && w.UsedPercent == nil && !rejected {
		w.Reason = "missing_utilization"
	}
	if w.Reason != "" {
		return w
	}
	if timingReason != "" {
		w.State, w.Reason = quotaWindowTimingState(timingReason), timingReason
	} else if !resetAt.After(now) {
		w.State, w.Reason = "stale", "reset_elapsed"
	} else if rejected || (w.UsedPercent != nil && *w.UsedPercent >= quotaExhaustedUtilization*100) {
		w.State, w.Reason = "exhausted", "window_exhausted"
	} else {
		w.State = "known"
	}
	return w
}

// All present business fields of a window must come from the same acquisition.
// An optional reset/status without provenance cannot silently borrow the latest
// usage timestamp. Separate windows can, and do, retain different timestamps.
func quotaWindowObservation(w *QuotaWindowView, signals map[string]string, observation QuotaState, fields []string, now time.Time, provenance QuotaWindowProvenance) (time.Time, bool, string) {
	var acquired time.Time
	present, missing, mixed := false, false, false
	for _, key := range fields {
		if _, exists := quotaSignal(signals, key); !exists {
			continue
		}
		present = true
		at := observation.SignalObservedAt[http.CanonicalHeaderKey(key)]
		if at.IsZero() {
			missing = true
			continue
		}
		if !acquired.IsZero() && !at.Equal(acquired) {
			mixed = true
		}
		if acquired.IsZero() || at.Before(acquired) {
			acquired = at
		}
	}
	verified := present && !missing && !mixed && !acquired.IsZero()
	observed := acquired
	w.TimestampBasis = "unknown"
	if verified {
		w.TimestampBasis = "header_acquisition"
	} else if observed.IsZero() {
		observed = observation.ObservedAt
		if provenance.TimestampBasis == "request_started" || provenance.TimestampBasis == "legacy_result_handled" {
			w.TimestampBasis = provenance.TimestampBasis
		}
	}
	w.ObservedAt, w.AgeSeconds = nil, nil
	if observed.IsZero() {
		return observed, false, "missing_observed_at"
	}
	epoch, age := quotaWindowEpoch(observed), now.Sub(observed).Seconds()
	w.ObservedAt, w.AgeSeconds = &epoch, &age
	if now.IsZero() {
		return observed, false, "missing_now"
	}
	if observed.After(now) {
		return observed, false, "future_observed_at"
	}
	if mixed {
		return observed, false, "mixed_observation_times"
	}
	if !verified {
		return observed, false, "unverified_observation_time"
	}
	if age > 300 {
		return observed, true, "observation_expired"
	}
	return observed, true, ""
}

func quotaWindowReset(w *QuotaWindowView, signals map[string]string, observation QuotaState, absoluteKey, relativeKey string, observed time.Time, verified bool, now time.Time, claude bool) (time.Time, string) {
	base := observed
	if base.IsZero() || base.After(now) {
		base = now
	}
	var absolute, resetAt time.Time
	reason := ""
	if raw, exists := quotaSignal(signals, absoluteKey); exists {
		var ok bool
		absolute, ok = quotaWindowTimestamp(raw)
		if !ok || absolute.After(base.Add(quotaMaxResetHorizon)) {
			reason = "invalid_absolute_reset"
			w.Diagnostics = append(w.Diagnostics, QuotaWindowDiagnostic{Code: reason})
		} else {
			epoch := quotaWindowEpoch(absolute)
			w.ResetAt = &epoch
			resetAt = absolute
		}
	}
	if !claude {
		if raw, exists := quotaSignal(signals, relativeKey); exists {
			seconds, ok := quotaWindowFloat(raw, quotaMaxResetHorizon.Seconds())
			if !ok {
				w.Diagnostics = append(w.Diagnostics, QuotaWindowDiagnostic{Code: "invalid_relative_reset"})
				if reason == "" {
					reason = "invalid_relative_reset"
				}
			} else {
				diagnostic := QuotaWindowDiagnostic{RelativeResetSeconds: &seconds}
				// The relative field needs its own acquired base. Legacy
				// observation times permit an explicitly unresolved comparison,
				// not a newly verified relative reset.
				relativeBase := observation.SignalObservedAt[http.CanonicalHeaderKey(relativeKey)]
				relativeVerified := !relativeBase.IsZero() && !relativeBase.After(now)
				if relativeBase.IsZero() {
					relativeBase = observed
				}
				var implied time.Time
				if !relativeBase.IsZero() {
					implied = relativeBase.Add(time.Duration(seconds * float64(time.Second)))
					epoch := quotaWindowEpoch(implied)
					diagnostic.ImpliedResetAt = &epoch
				}
				switch {
				case !relativeVerified || !verified:
					diagnostic.Code = "unresolved_relative_timing"
				case w.ResetAt != nil:
					diagnostic.Code = "relative_reset_agrees"
				default:
					diagnostic.Code = "relative_reset_only"
				}
				if w.ResetAt != nil && !implied.IsZero() {
					deltaDuration := absolute.Sub(implied)
					delta := deltaDuration.Seconds()
					diagnostic.ResetDeltaSeconds = &delta
					if relativeVerified && verified && (deltaDuration > 10*time.Second || deltaDuration < -10*time.Second) {
						diagnostic.Code = "relative_reset_disagreement"
					}
				} else if reason == "" && relativeVerified && verified {
					epoch := quotaWindowEpoch(implied)
					w.ResetAt = &epoch
					resetAt = implied
				}
				w.Diagnostics = append(w.Diagnostics, diagnostic)
			}
		}
	}
	if reason == "" && w.ResetAt == nil {
		reason = "missing_reset"
	}
	return resetAt, reason
}

func quotaWindowFloat(raw string, maximum float64) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if !quotaWindowDecimal.MatchString(raw) {
		return 0, false
	}
	value, ok := parseQuotaFloat(raw)
	return value, ok && value <= maximum
}

func quotaWindowMinutes(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	for _, char := range raw {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	minutes, err := strconv.ParseInt(raw, 10, 64)
	return minutes, err == nil && minutes <= math.MaxInt64/60
}

func quotaWindowTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if !quotaWindowDecimal.MatchString(raw) {
		if _, err := time.Parse(time.RFC3339, raw); err != nil {
			return time.Time{}, false
		}
	}
	at, ok := parseQuotaTimestamp(raw)
	if !ok || !at.After(time.Unix(0, 0)) {
		return time.Time{}, false
	}
	// Keep subsecond reset comparisons at time.Time precision. Parsing a
	// contemporary epoch as float64 first can round a genuine >10s disagreement
	// down to the accepted 10s boundary. Native millisecond handling remains.
	if quotaWindowDecimal.MatchString(raw) {
		whole, fraction, _ := strings.Cut(raw, ".")
		seconds, err := strconv.ParseInt(whole, 10, 64)
		if err == nil && seconds <= 1e12 {
			if len(fraction) > 9 {
				fraction = fraction[:9]
			}
			fraction += strings.Repeat("0", 9-len(fraction))
			nanos, errNanos := strconv.ParseInt(fraction, 10, 64)
			if errNanos == nil {
				at = time.Unix(seconds, nanos)
			}
		}
	}
	return at, true
}

func quotaWindowBool(signals map[string]string, key string) *bool {
	switch strings.ToLower(quotaSignalValue(signals, key)) {
	case "true":
		value := true
		return &value
	case "false":
		value := false
		return &value
	default:
		return nil
	}
}

func quotaWindowEpoch(at time.Time) float64 {
	return float64(at.Unix()) + float64(at.Nanosecond())/1e9
}

func quotaWindowHasPrefix(signals map[string]string, prefix string) bool {
	for key := range signals {
		if strings.HasPrefix(strings.ToLower(key), strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

func quotaWindowCodexPrefixes(signals map[string]string) []string {
	prefixes := map[string]bool{"x-codex-": true}
	for key := range signals {
		key = strings.ToLower(key)
		if !strings.HasPrefix(key, "x-codex-") {
			continue
		}
		matchedWindow := false
		for _, slot := range []string{"primary", "secondary"} {
			for _, suffix := range []string{"used-percent", "window-minutes", "reset-at", "reset-after-seconds", "allowed", "limit-reached"} {
				ending := slot + "-" + suffix
				if strings.HasSuffix(key, "-"+ending) {
					prefixes[strings.TrimSuffix(key, ending)] = true
					matchedWindow = true
				}
			}
		}
		if matchedWindow {
			continue
		}
		for _, suffix := range []string{"allowed", "limit-reached", "limit-name"} {
			if strings.HasSuffix(key, "-"+suffix) {
				prefixes[strings.TrimSuffix(key, suffix)] = true
			}
		}
	}
	result := make([]string, 0, len(prefixes))
	for prefix := range prefixes {
		result = append(result, prefix)
	}
	sort.Strings(result)
	return result
}

func quotaWindowLimitSignals(provider string, signals map[string]string) map[string]string {
	facts := make(map[string]string)
	for key, value := range signals {
		lower := strings.ToLower(key)
		keep := lower == "retry-after"
		if provider == "claude" {
			switch lower {
			case "anthropic-ratelimit-unified-status", "anthropic-ratelimit-unified-reset",
				"anthropic-ratelimit-unified-fallback", "anthropic-ratelimit-unified-fallback-percentage",
				"anthropic-ratelimit-unified-representative-claim", "anthropic-ratelimit-unified-overage-status",
				"anthropic-ratelimit-unified-overage-disabled-reason":
				keep = true
			}
		} else if strings.HasPrefix(lower, "x-codex-") {
			keep = keep || strings.HasSuffix(lower, "-allowed") || strings.HasSuffix(lower, "-limit-reached") || strings.HasSuffix(lower, "-limit-name")
		}
		if keep {
			facts[key] = value
		}
	}
	return facts
}

func quotaWindowTimingState(reason string) string {
	if reason == "observation_expired" {
		return "stale"
	}
	return "unknown"
}

func quotaWindowsState(windows []QuotaWindowView) string {
	// Exhaustion is retained despite valid/unknown siblings. No reduction is
	// an authorization decision, particularly with an aggregate refusal.
	for _, state := range []string{"exhausted", "unknown", "stale", "known"} {
		for _, window := range windows {
			if window.State == state {
				return state
			}
		}
	}
	if len(windows) > 0 {
		return "not_applicable"
	}
	return "unknown"
}
