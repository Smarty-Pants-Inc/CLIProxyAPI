package auth

import (
	"encoding/json"
	"math"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Keep reason: this is the provider-data/acquisition trust boundary. These
// fixtures reproduce db.redacted_examples (NOT database.redacted_examples) in
// the staged D54 evidence.json, events 20014286 and 20014285. Their event
// acquisition times are unknown; the fixed acquired times below are synthetic.
func quotaWindowsProductionHeaders(provider string) http.Header {
	if provider == "claude" {
		return http.Header{
			"Anthropic-Ratelimit-Unified-5h-Reset":                {"1793870400"},
			"Anthropic-Ratelimit-Unified-5h-Status":               {"allowed"},
			"Anthropic-Ratelimit-Unified-5h-Utilization":          {"0.29"},
			"Anthropic-Ratelimit-Unified-7d-Reset":                {"1793880000"},
			"Anthropic-Ratelimit-Unified-7d-Status":               {"allowed"},
			"Anthropic-Ratelimit-Unified-7d-Utilization":          {"0.56"},
			"Anthropic-Ratelimit-Unified-Fallback-Percentage":     {"0.5"},
			"Anthropic-Ratelimit-Unified-Overage-Disabled-Reason": {"org_level_disabled"},
			"Anthropic-Ratelimit-Unified-Overage-Status":          {"rejected"},
			"Anthropic-Ratelimit-Unified-Representative-Claim":    {"five_hour"},
			"Anthropic-Ratelimit-Unified-Reset":                   {"1793870400"},
			"Anthropic-Ratelimit-Unified-Status":                  {"allowed"},
			"Request-Id":                                          {"<redacted-request-id>"},
		}
	}
	return http.Header{
		"X-Codex-Active-Limit":                         {"premium"},
		"X-Codex-Credits-Balance":                      {"0"},
		"X-Codex-Credits-Has-Credits":                  {"False"},
		"X-Codex-Credits-Unlimited":                    {"False"},
		"X-Codex-Plan-Type":                            {"pro"},
		"X-Codex-Primary-Over-Secondary-Limit-Percent": {"0"},
		"X-Codex-Primary-Reset-After-Seconds":          {"524096"},
		"X-Codex-Primary-Reset-At":                     {"1794380046"},
		"X-Codex-Primary-Used-Percent":                 {"9"},
		"X-Codex-Primary-Window-Minutes":               {"10080"},
		"X-Codex-Safety-Buffering-Enabled":             {"true"},
		"X-Codex-Safety-Buffering-Faster-Model":        {"gpt-6-luna"},
		"X-Codex-Secondary-Reset-After-Seconds":        {"0"},
		"X-Codex-Secondary-Reset-At":                   {""},
		"X-Codex-Secondary-Used-Percent":               {"0"},
		"X-Codex-Secondary-Window-Minutes":             {"0"},
		"X-Oai-Request-Id":                             {"<redacted-request-id>"},
	}
}

func quotaWindowsAcquired(signals map[string]string, at time.Time) QuotaState {
	q := QuotaState{Signals: signals, ObservedAt: at, SignalObservedAt: make(map[string]time.Time)}
	for key := range signals {
		q.SignalObservedAt[http.CanonicalHeaderKey(key)] = at
	}
	return q
}

func quotaWindowsBaseSignals(now time.Time) map[string]string {
	return map[string]string{
		"X-Codex-Primary-Used-Percent":     "10",
		"X-Codex-Primary-Window-Minutes":   "300",
		"X-Codex-Primary-Reset-At":         strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
		"X-Codex-Secondary-Window-Minutes": "0",
	}
}

func quotaWindowsFind(t *testing.T, view QuotaWindowsView, limit, slot string) QuotaWindowView {
	t.Helper()
	for _, window := range view.Windows {
		if window.LimitKey == limit && window.UpstreamWindow == slot {
			return window
		}
	}
	t.Fatalf("missing window %q/%q in %+v", limit, slot, view.Windows)
	return QuotaWindowView{}
}

func quotaWindowsNumber(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil || math.Abs(*got-want) > 1e-6 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func quotaWindowsNumberPrecise(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil || math.Abs(*got-want) > 1e-12 {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}

func quotaWindowsDiagnostic(t *testing.T, window QuotaWindowView, code string) QuotaWindowDiagnostic {
	t.Helper()
	for _, diagnostic := range window.Diagnostics {
		if diagnostic.Code == code {
			return diagnostic
		}
	}
	t.Fatalf("missing diagnostic %q: %+v", code, window)
	return QuotaWindowDiagnostic{}
}

func TestNormalizeQuotaWindowsProductionFixtures(t *testing.T) {
	// Arithmetic base for a timing fixture, not a recovered event timestamp.
	acquired := time.Unix(1793855950, 0)
	provenance := QuotaWindowProvenance{Source: "passive_http"}
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			headers := quotaWindowsProductionHeaders(provider)
			signals := collectQuotaSignals(provider, headers)
			for key := range signals {
				if strings.Contains(strings.ToLower(key), "request-id") || strings.Contains(key, "Safety-Buffering") {
					t.Fatalf("excluded hint or ID leaked: %s", key)
				}
			}
			q := quotaWindowsAcquired(signals, acquired)
			view := NormalizeQuotaWindows(provider, q, acquired.Add(time.Second), provenance)
			if view.State != "known" || len(view.Windows) != 2 {
				t.Fatalf("unexpected fixture view: %+v", view)
			}
			if provider == "claude" {
				for _, expected := range []struct {
					slot        string
					duration    int64
					used, reset float64
				}{{"5h", 18000, 29, 1793870400}, {"7d", 604800, 56, 1793880000}} {
					w := quotaWindowsFind(t, view, "unified", expected.slot)
					if w.State != "known" || w.DurationSeconds == nil || *w.DurationSeconds != expected.duration {
						t.Fatalf("bad Claude window: %+v", w)
					}
					quotaWindowsNumber(t, "used", w.UsedPercent, expected.used)
					quotaWindowsNumber(t, "headroom", w.HeadroomPercent, 100-expected.used)
					quotaWindowsNumber(t, "reset", w.ResetAt, expected.reset)
				}
				if view.Credits.OverageStatus != "rejected" || view.Credits.OverageDisabledReason != "org_level_disabled" || view.LimitSignals["Anthropic-Ratelimit-Unified-Representative-Claim"] != "five_hour" {
					t.Fatalf("missing Claude metadata: %+v", view)
				}
			} else {
				w := quotaWindowsFind(t, view, "x-codex", "primary")
				if w.DurationSeconds == nil || *w.DurationSeconds != 604800 {
					t.Fatalf("primary was classified by slot, not duration: %+v", w)
				}
				quotaWindowsNumber(t, "used", w.UsedPercent, 9)
				quotaWindowsNumber(t, "headroom", w.HeadroomPercent, 91)
				quotaWindowsNumber(t, "reset", w.ResetAt, 1794380046)
				quotaWindowsDiagnostic(t, w, "relative_reset_agrees")
				absent := quotaWindowsFind(t, view, "x-codex", "secondary")
				if absent.State != "not_applicable" || absent.Reason != "upstream_absent" || absent.DurationSeconds != nil || absent.UsedPercent != nil || absent.HeadroomPercent != nil || absent.ResetAt != nil {
					t.Fatalf("absent secondary became free capacity: %+v", absent)
				}
				if view.Plan != "pro" || view.ActiveLimit != "premium" || view.Credits.HasCredits == nil || *view.Credits.HasCredits || view.Credits.Unlimited == nil || *view.Credits.Unlimited {
					t.Fatalf("incorrect Codex metadata: %+v", view)
				}
				quotaWindowsNumber(t, "balance", view.Credits.Balance, 0)
			}
			// The same scalar representation, with the same explicit synthetic
			// provenance, produces identical output after case normalization.
			lower := make(map[string]string)
			for key, value := range signals {
				lower[strings.ToLower(key)] = value
			}
			if got := NormalizeQuotaWindows(strings.ToUpper(provider), quotaWindowsAcquired(lower, acquired), acquired.Add(time.Second), provenance); !reflect.DeepEqual(view, got) {
				t.Fatalf("case-insensitive scalar projection differs: %+v vs %+v", view, got)
			}
			legacy := NormalizeQuotaWindows(provider, QuotaState{Signals: signals, ObservedAt: acquired}, acquired.Add(time.Second), QuotaWindowProvenance{Source: "usage_events", TimestampBasis: "header_acquisition"})
			for _, w := range legacy.Windows {
				if w.State != "unknown" || w.TimestampBasis == "header_acquisition" {
					t.Fatalf("legacy fixture was falsely acquired: %+v", w)
				}
			}
		})
	}
}

func TestNormalizeQuotaHeaderWindowsAdapter(t *testing.T) {
	acquired := time.Unix(1793855950, 0)
	for _, provider := range []string{"claude", "codex"} {
		headers := quotaWindowsProductionHeaders(provider)
		beforeHeaders := headers.Clone()
		signals := collectQuotaSignals(provider, headers)
		q := quotaWindowsAcquired(signals, acquired)
		beforeTimes := make(map[string]time.Time, len(q.SignalObservedAt))
		for key, at := range q.SignalObservedAt {
			beforeTimes[key] = at
		}
		provenance := QuotaWindowProvenance{Source: "usage_events", TimestampBasis: "header_acquisition"}
		got := NormalizeQuotaHeaderWindows(provider, headers, q.SignalObservedAt, acquired, provenance)
		want := NormalizeQuotaWindows(provider, q, acquired, provenance)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("header adapter differs from native state projection: %+v vs %+v", got, want)
		}
		for _, window := range got.Windows {
			if window.TimestampBasis != "header_acquisition" {
				t.Fatalf("verified acquisition used a noncanonical wire label: %+v", window)
			}
		}
		lowerTimes := make(map[string]time.Time)
		for key, at := range q.SignalObservedAt {
			lowerTimes[strings.ToLower(key)] = at
		}
		lowerTimes["Request-Id"] = acquired.Add(time.Hour)
		if lower := NormalizeQuotaHeaderWindows(provider, headers, lowerTimes, acquired, provenance); !reflect.DeepEqual(lower, want) {
			t.Fatalf("adapter did not pair only matching canonical timestamp keys: %+v", lower)
		}
		legacy := NormalizeQuotaHeaderWindows(provider, headers, nil, acquired, provenance)
		for _, window := range legacy.Windows {
			if window.State != "unknown" || window.TimestampBasis == "header_acquisition" || window.ObservedAt != nil || window.AgeSeconds != nil {
				t.Fatalf("header-only capture invented acquisition: %+v", window)
			}
		}
		if !reflect.DeepEqual(headers, beforeHeaders) || !reflect.DeepEqual(q.SignalObservedAt, beforeTimes) {
			t.Fatal("header adapter mutated caller maps")
		}
	}
}

// Keep reason: duplicate-case quota evidence crosses the input-data trust
// boundary. Neither map iteration nor sorted overwriting may choose its truth.
func TestNormalizeQuotaWindowsConflictingCanonicalHeaders(t *testing.T) {
	acquired := time.Unix(1793855950, 0)
	provenance := QuotaWindowProvenance{Source: "usage_events"}
	for _, conflict := range []string{"value", "acquisition_time"} {
		t.Run(conflict, func(t *testing.T) {
			headers := quotaWindowsProductionHeaders("codex")
			q := quotaWindowsAcquired(collectQuotaSignals("codex", headers), acquired)
			// The reported sequence adds a lowercase counterpart to the
			// canonical usage header while keeping a coherent timestamp map.
			headers["x-codex-primary-used-percent"] = []string{"9"}
			q.Signals["x-codex-primary-used-percent"] = "9"
			if conflict == "value" {
				headers["x-codex-primary-used-percent"] = []string{"99"}
				q.Signals["x-codex-primary-used-percent"] = "99"
			} else {
				q.SignalObservedAt["x-codex-primary-used-percent"] = acquired.Add(time.Second)
			}
			beforeHeaders, before := headers.Clone(), q.Clone()
			view := NormalizeQuotaHeaderWindows("codex", headers, q.SignalObservedAt, acquired, provenance)
			if view.State != "unknown" || view.Reason != "conflicting_header_evidence" || view.Windows == nil || len(view.Windows) != 0 {
				t.Fatalf("ambiguous observation retained admission evidence: %+v", view)
			}
			for range 100 {
				if again := NormalizeQuotaHeaderWindows("codex", headers, q.SignalObservedAt, acquired, provenance); !reflect.DeepEqual(view, again) {
					t.Fatalf("header conflict was nondeterministic: %+v vs %+v", view, again)
				}
				if scalar := NormalizeQuotaWindows("codex", q, acquired, provenance); !reflect.DeepEqual(view, scalar) {
					t.Fatalf("scalar conflict chose a value: %+v vs %+v", view, scalar)
				}
			}
			if !reflect.DeepEqual(headers, beforeHeaders) || !reflect.DeepEqual(q, before) {
				t.Fatal("conflict rejection mutated caller evidence")
			}
		})
	}
}

func TestNormalizeQuotaWindowsMixedCaseCanonicalAgreement(t *testing.T) {
	acquired := time.Unix(1793855950, 0)
	provenance := QuotaWindowProvenance{Source: "usage_events"}
	canonical := quotaWindowsAcquired(quotaWindowsBaseSignals(acquired), acquired)
	want := NormalizeQuotaWindows("codex", canonical, acquired, provenance)
	if want.State != "known" {
		t.Fatalf("invalid known counterexample: %+v", want)
	}
	for _, duplicates := range []bool{false, true} {
		headers := http.Header{
			"X-Codex-Primary-Used-Percent":     {"99", "10"},
			"x-codex-primary-window-minutes":   {"300"},
			"X-CODEX-PRIMARY-RESET-AT":         {canonical.Signals["X-Codex-Primary-Reset-At"]},
			"x-Codex-Secondary-Window-Minutes": {"0"},
		}
		signals := make(map[string]string, len(headers))
		for key, values := range headers {
			signals[key] = values[len(values)-1]
		}
		q := quotaWindowsAcquired(signals, acquired)
		if duplicates {
			// Different earlier array entries are irrelevant; equal trimmed
			// last values and equal acquisition times are unambiguous.
			headers["x-codex-primary-used-percent"] = []string{"0", " 10 "}
			q.Signals["x-codex-primary-used-percent"] = " 10 "
			q.SignalObservedAt["x-codex-primary-used-percent"] = acquired
		}
		if got := NormalizeQuotaHeaderWindows("codex", headers, q.SignalObservedAt, acquired, provenance); !reflect.DeepEqual(want, got) {
			t.Fatalf("valid mixed-case headers changed (duplicates=%v): %+v vs %+v", duplicates, want, got)
		}
		if got := NormalizeQuotaWindows("codex", q, acquired, provenance); !reflect.DeepEqual(want, got) {
			t.Fatalf("valid mixed-case scalar signals changed (duplicates=%v): %+v vs %+v", duplicates, want, got)
		}
		w := quotaWindowsFind(t, want, "x-codex", "primary")
		if w.TimestampBasis != "header_acquisition" {
			t.Fatalf("canonical acquisition wire label changed: %+v", w)
		}
		quotaWindowsNumber(t, "last array value", w.UsedPercent, 10)
	}
}

func TestNormalizeQuotaWindowsFreshCaptureIsUnverified(t *testing.T) {
	// Exact numeric shapes from quota-capture-2026-11-05T104539Z.json.
	// timestamp_ms is request time, created_at_ms is row-insert time, and
	// captured_at is capture time. None is an upstream acquisition timestamp.
	capture := time.Date(2026, 11, 5, 10, 45, 39, 0, time.UTC)
	claude := quotaWindowsProductionHeaders("claude")
	for _, suffix := range []string{"Reset", "Status", "Utilization"} {
		claude.Del("Anthropic-Ratelimit-Unified-5h-" + suffix)
	}
	claude.Del("Request-Id")
	claude.Set("Anthropic-Ratelimit-Unified-7d-Reset", "1793923200")
	claude.Set("Anthropic-Ratelimit-Unified-7d-Utilization", "0.53")
	claude.Set("Anthropic-Ratelimit-Unified-Reset", "1793923200")
	claude.Set("Anthropic-Ratelimit-Unified-Representative-Claim", "seven_day")
	codex := quotaWindowsProductionHeaders("codex")
	codex.Del("X-Oai-Request-Id")
	codex.Set("X-Codex-Primary-Reset-After-Seconds", "504864")
	codex.Set("X-Codex-Primary-Reset-At", "1794380322")
	codex.Set("X-Codex-Primary-Used-Percent", "5")
	for _, tc := range []struct {
		provider            string
		headers             http.Header
		requestMS, insertMS int64
		limit, slot         string
		used, reset         float64
	}{
		{"claude", claude, 1793875522759, 1793875534543, "unified", "7d", 53, 1793923200},
		{"codex", codex, 1793875459059, 1793875522055, "x-codex", "primary", 5, 1794380322},
	} {
		for _, at := range []time.Time{time.UnixMilli(tc.requestMS), time.UnixMilli(tc.insertMS), capture} {
			view := NormalizeQuotaWindows(tc.provider, QuotaState{Signals: collectQuotaSignals(tc.provider, tc.headers), ObservedAt: at}, capture, QuotaWindowProvenance{Source: "usage_events", TimestampBasis: "request_started"})
			w := quotaWindowsFind(t, view, tc.limit, tc.slot)
			if w.State != "unknown" || w.Reason != "unverified_observation_time" || w.TimestampBasis != "request_started" {
				t.Fatalf("request/insert/capture time freshened evidence: %+v", w)
			}
			quotaWindowsNumber(t, "used", w.UsedPercent, tc.used)
			quotaWindowsNumber(t, "reset", w.ResetAt, tc.reset)
			if tc.provider == "codex" {
				quotaWindowsDiagnostic(t, w, "unresolved_relative_timing")
			}
		}
	}
}

func TestNormalizeQuotaWindowsDurationAndAbsence(t *testing.T) {
	now := time.Unix(1793855950, 0)
	for _, tc := range []struct {
		name, minutes, state, reason string
		duration                     int64
	}{
		{"weekly_primary", "10080", "known", "", 604800},
		{"alternate", "90", "known", "", 5400},
		{"absent", "0", "not_applicable", "upstream_absent", 0},
		{"missing", "", "unknown", "missing_duration", 0},
		{"negative", "-1", "unknown", "invalid_duration", 0},
		{"fractional", "1.5", "unknown", "invalid_duration", 0},
		{"decimal_integral", "300.0", "unknown", "invalid_duration", 0},
		{"exponent", "3e2", "unknown", "invalid_duration", 0},
		{"percent", "300%", "unknown", "invalid_duration", 0},
		{"not_finite", "NaN", "unknown", "invalid_duration", 0},
		{"overflow_multiply", "153722867280912931", "unknown", "invalid_duration", 0},
		{"overflow_parse", "999999999999999999999999", "unknown", "invalid_duration", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signals := quotaWindowsBaseSignals(now)
			if tc.minutes == "" {
				delete(signals, "X-Codex-Primary-Window-Minutes")
			} else {
				signals["X-Codex-Primary-Window-Minutes"] = tc.minutes
			}
			view := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
			w := quotaWindowsFind(t, view, "x-codex", "primary")
			if w.State != tc.state || w.Reason != tc.reason {
				t.Fatalf("got %+v, want %s/%s", w, tc.state, tc.reason)
			}
			if tc.name == "absent" && view.State != "not_applicable" {
				t.Fatalf("all explicit absent slots did not reduce to not_applicable: %+v", view)
			}
			if tc.duration == 0 {
				if w.DurationSeconds != nil {
					t.Fatalf("unknown/absent duration was invented: %+v", w)
				}
			} else if w.DurationSeconds == nil || *w.DurationSeconds != tc.duration {
				t.Fatalf("duration = %v, want %d", w.DurationSeconds, tc.duration)
			}
		})
	}
	// Both source slots can report arbitrary positive durations, including
	// the reverse of the historical primary=5h/secondary=week assumption.
	signals := quotaWindowsBaseSignals(now)
	signals["X-Codex-Primary-Window-Minutes"] = "10080"
	signals["X-Codex-Secondary-Window-Minutes"] = "300"
	signals["X-Codex-Secondary-Used-Percent"] = "0"
	signals["X-Codex-Secondary-Reset-At"] = signals["X-Codex-Primary-Reset-At"]
	view := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
	if view.Windows[0].UpstreamWindow != "secondary" || *view.Windows[0].DurationSeconds != 18000 || *view.Windows[1].DurationSeconds != 604800 {
		t.Fatalf("windows not sorted/classified by actual duration: %+v", view.Windows)
	}
	quotaWindowsNumber(t, "true zero usage", view.Windows[0].UsedPercent, 0)
	quotaWindowsNumber(t, "measured full headroom", view.Windows[0].HeadroomPercent, 100)
}

func TestNormalizeQuotaWindowsRejectsMalformedUtilization(t *testing.T) {
	now := time.Unix(1793855950, 0)
	for _, provider := range []string{"claude", "codex"} {
		invalid := []string{"NaN", "Inf", "+Inf", "-1", "1e0", "1%", "1.2.3", "999999999999999999999999999999999999999999999999999999"}
		if provider == "claude" {
			invalid = append(invalid, "1.0001", "29")
		} else {
			invalid = append(invalid, "100.0001")
		}
		for _, raw := range invalid {
			t.Run(provider+"/"+raw, func(t *testing.T) {
				signals := quotaWindowsBaseSignals(now)
				key, limit, slot := "X-Codex-Primary-Used-Percent", "x-codex", "primary"
				if provider == "claude" {
					signals = collectQuotaSignals(provider, quotaWindowsProductionHeaders(provider))
					key, limit, slot = "Anthropic-Ratelimit-Unified-5h-Utilization", "unified", "5h"
				}
				signals[key] = raw
				w := quotaWindowsFind(t, NormalizeQuotaWindows(provider, quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{}), limit, slot)
				if w.State != "unknown" || w.Reason != "invalid_utilization" || w.UsedPercent != nil || w.HeadroomPercent != nil {
					t.Fatalf("malformed utilization became usable/clamped: %+v", w)
				}
			})
		}
	}
}

func TestNormalizeQuotaWindowsResetEvidence(t *testing.T) {
	acquired := time.Unix(1793855950, 250000000)
	for _, tc := range []struct {
		name, absolute, relative, state, reason, diagnostic string
		verified                                            bool
		reset                                               *float64
	}{
		{"absolute_only", "1793859550.25", "", "known", "", "", true, quotaWindowsFloatPointer(1793859550.25)},
		{"milliseconds", "1793859550250", "", "known", "", "", true, quotaWindowsFloatPointer(1793859550.25)},
		{"rfc3339", "2026-11-05T06:19:10.25Z", "", "known", "", "", true, quotaWindowsFloatPointer(1793859550.25)},
		{"relative_only", "", "3600", "known", "", "relative_reset_only", true, quotaWindowsFloatPointer(1793859550.25)},
		{"legacy_relative", "", "3600", "unknown", "missing_reset", "unresolved_relative_timing", false, nil},
		{"agrees", "1793859550.25", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859550.25)},
		{"one_second", "1793859551.25", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859551.25)},
		{"just_over_one_second", "1793859551.250000001", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859551.250000001)},
		{"fractional_difference", "1793859551.5", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859551.5)},
		{"negative_difference", "1793859549", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859549)},
		{"exact_positive_ten_seconds", "1793859560.25", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859560.25)},
		{"exact_negative_ten_seconds", "1793859540.25", "3600", "known", "", "relative_reset_agrees", true, quotaWindowsFloatPointer(1793859540.25)},
		{"positive_ten_seconds_plus_one_ns", "1793859560.250000001", "3600", "known", "", "relative_reset_disagreement", true, quotaWindowsFloatPointer(1793859560.250000001)},
		{"negative_ten_seconds_minus_one_ns", "1793859540.249999999", "3600", "known", "", "relative_reset_disagreement", true, quotaWindowsFloatPointer(1793859540.249999999)},
		{"legacy_dual", "1793859559", "3600", "unknown", "unverified_observation_time", "unresolved_relative_timing", false, quotaWindowsFloatPointer(1793859559)},
		{"bad_absolute_no_fallback", "NaN", "3600", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"negative_absolute", "-1", "3600", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"percent_absolute", "1793859550%", "3600", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"exponent_absolute", "1.79385955e9", "3600", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"huge_absolute", "99999999999999999999999999", "3600", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"horizon_absolute", "1796534351", "", "unknown", "invalid_absolute_reset", "invalid_absolute_reset", true, nil},
		{"negative_relative", "1793859550.25", "-1", "unknown", "invalid_relative_reset", "invalid_relative_reset", true, quotaWindowsFloatPointer(1793859550.25)},
		{"horizon_relative", "", "2592001", "unknown", "invalid_relative_reset", "invalid_relative_reset", true, nil},
		{"huge_relative", "", "999999999999999999999999", "unknown", "invalid_relative_reset", "invalid_relative_reset", true, nil},
		{"exponent_relative", "", "3.6e3", "unknown", "invalid_relative_reset", "invalid_relative_reset", true, nil},
		{"no_reset", "", "", "unknown", "missing_reset", "", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signals := quotaWindowsBaseSignals(acquired)
			delete(signals, "X-Codex-Primary-Reset-At")
			if tc.absolute != "" {
				signals["X-Codex-Primary-Reset-At"] = tc.absolute
			}
			if tc.relative != "" {
				signals["X-Codex-Primary-Reset-After-Seconds"] = tc.relative
			}
			q := QuotaState{Signals: signals, ObservedAt: acquired}
			if tc.verified {
				q = quotaWindowsAcquired(signals, acquired)
			}
			w := quotaWindowsFind(t, NormalizeQuotaWindows("codex", q, acquired, QuotaWindowProvenance{}), "x-codex", "primary")
			if w.State != tc.state || w.Reason != tc.reason {
				t.Fatalf("got %+v, want %s/%s", w, tc.state, tc.reason)
			}
			if tc.reset == nil {
				if w.ResetAt != nil {
					t.Fatalf("invented reset: %+v", w)
				}
			} else {
				quotaWindowsNumber(t, "preferred reset", w.ResetAt, *tc.reset)
			}
			if tc.diagnostic != "" {
				d := quotaWindowsDiagnostic(t, w, tc.diagnostic)
				if tc.diagnostic == "relative_reset_disagreement" || tc.diagnostic == "relative_reset_agrees" || tc.diagnostic == "unresolved_relative_timing" {
					quotaWindowsNumber(t, "relative seconds", d.RelativeResetSeconds, 3600)
					quotaWindowsNumber(t, "implied reset", d.ImpliedResetAt, 1793859550.25)
					if tc.absolute != "" {
						absolute, ok := quotaWindowTimestamp(tc.absolute)
						if !ok || d.ResetDeltaSeconds == nil {
							t.Fatalf("dual reset comparison lost valid delta: %+v", d)
						}
						wantDelta := absolute.Sub(acquired.Add(time.Hour)).Seconds()
						quotaWindowsNumberPrecise(t, "signed reset delta", d.ResetDeltaSeconds, wantDelta)
					}
					if tc.diagnostic == "relative_reset_disagreement" && w.State == "unknown" {
						t.Fatalf("relative disagreement alone made absolute evidence unknown: %+v", w)
					}
				}
			}
		})
	}
}

func TestNormalizeQuotaWindowsCodexAbsoluteResetRow20198112(t *testing.T) {
	acquired := time.Date(2026, 11, 6, 11, 33, 52, 196199291, time.UTC)
	headers := http.Header{
		"X-Codex-Primary-Used-Percent":          {"15"},
		"X-Codex-Primary-Window-Minutes":        {"10080"},
		"X-Codex-Primary-Reset-At":              {"1794379849"},
		"X-Codex-Primary-Reset-After-Seconds":   {"415019"},
		"X-Codex-Secondary-Used-Percent":        {"0"},
		"X-Codex-Secondary-Window-Minutes":      {"0"},
		"X-Codex-Secondary-Reset-At":            {""},
		"X-Codex-Secondary-Reset-After-Seconds": {"0"},
	}
	observation := quotaWindowsAcquired(collectQuotaSignals("codex", headers), acquired)
	// Preserve the explicit acquisition for the supplied blank absolute field;
	// collection correctly omits its empty value as a quota signal.
	observation.SignalObservedAt["X-Codex-Secondary-Reset-At"] = acquired
	for key, at := range observation.SignalObservedAt {
		if !at.Equal(acquired) {
			t.Fatalf("field %q has acquisition %s, want %s", key, at, acquired)
		}
	}

	provenance := QuotaWindowProvenance{Source: "usage_events", TimestampBasis: "header_acquisition"}
	view := NormalizeQuotaWindows("codex", observation, acquired, provenance)
	if view.State != "known" {
		t.Fatalf("fresh absolute-reset evidence was not known: %+v", view)
	}
	primary := quotaWindowsFind(t, view, "x-codex", "primary")
	if primary.State != "known" || primary.DurationSeconds == nil || *primary.DurationSeconds != 604800 {
		t.Fatalf("unexpected primary window: %+v", primary)
	}
	quotaWindowsNumber(t, "used", primary.UsedPercent, 15)
	quotaWindowsNumber(t, "headroom", primary.HeadroomPercent, 85)
	quotaWindowsNumber(t, "absolute reset", primary.ResetAt, 1794379849)
	diagnostic := quotaWindowsDiagnostic(t, primary, "relative_reset_agrees")
	quotaWindowsNumber(t, "relative seconds", diagnostic.RelativeResetSeconds, 415019)
	implied := acquired.Add(415019 * time.Second)
	quotaWindowsNumber(t, "implied reset", diagnostic.ImpliedResetAt, quotaWindowEpoch(implied))
	quotaWindowsNumberPrecise(t, "signed reset delta", diagnostic.ResetDeltaSeconds, -2.196199291)
	for _, diagnostic := range primary.Diagnostics {
		if diagnostic.Code == "relative_reset_disagreement" {
			t.Fatalf("sub-threshold difference was reported as a disagreement: %+v", primary)
		}
	}
	secondary := quotaWindowsFind(t, view, "x-codex", "secondary")
	if secondary.State != "not_applicable" || secondary.Reason != "upstream_absent" || secondary.DurationSeconds != nil || secondary.UsedPercent != nil || secondary.HeadroomPercent != nil || secondary.ResetAt != nil {
		t.Fatalf("explicitly absent secondary became capacity: %+v", secondary)
	}

	for _, tc := range []struct {
		name, primaryState, primaryReason, secondaryState, secondaryReason string
		age                                                                time.Duration
	}{
		{"exactly_300_seconds", "known", "", "not_applicable", "upstream_absent", 300 * time.Second},
		{"over_300_seconds_by_1ns", "stale", "observation_expired", "stale", "observation_expired", 300*time.Second + time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeQuotaWindows("codex", observation, acquired.Add(tc.age), provenance)
			primary := quotaWindowsFind(t, got, "x-codex", "primary")
			secondary := quotaWindowsFind(t, got, "x-codex", "secondary")
			if primary.State != tc.primaryState || primary.Reason != tc.primaryReason {
				t.Fatalf("primary got %s/%s, want %s/%s: %+v", primary.State, primary.Reason, tc.primaryState, tc.primaryReason, primary)
			}
			if secondary.State != tc.secondaryState || secondary.Reason != tc.secondaryReason {
				t.Fatalf("secondary got %s/%s, want %s/%s: %+v", secondary.State, secondary.Reason, tc.secondaryState, tc.secondaryReason, secondary)
			}
		})
	}

	// Replaying this historical acquisition at a later date cannot make it
	// current capacity even though the recorded reset remains in the future.
	later := NormalizeQuotaWindows("codex", observation, acquired.Add(24*time.Hour), provenance)
	primary = quotaWindowsFind(t, later, "x-codex", "primary")
	if primary.State != "stale" || primary.Reason != "observation_expired" {
		t.Fatalf("historical replay became current capacity: %+v", primary)
	}
}

func quotaWindowsFloatPointer(value float64) *float64 { return &value }

func TestNormalizeQuotaWindowsFreshnessAndResetBoundaries(t *testing.T) {
	acquired := time.Unix(1793855950, 250000000)
	for _, tc := range []struct {
		name                string
		age                 time.Duration
		resetOffset         time.Duration
		used, state, reason string
	}{
		{"fresh", 0, time.Hour, "0", "known", ""},
		{"exact_300_seconds", 300 * time.Second, time.Hour, "10", "known", ""},
		{"over_300_seconds", 300*time.Second + time.Nanosecond, time.Hour, "10", "stale", "observation_expired"},
		{"future", -time.Nanosecond, time.Hour, "10", "unknown", "future_observed_at"},
		{"reset_now", 0, 0, "10", "stale", "reset_elapsed"},
		{"reset_just_future", 0, time.Nanosecond, "10", "known", ""},
		{"reset_past", 0, -time.Second, "98", "stale", "reset_elapsed"},
		{"below_native_threshold", 0, time.Hour, "97.999", "known", ""},
		{"native_threshold", 0, time.Hour, "98", "exhausted", "window_exhausted"},
		{"full", 0, time.Hour, "100", "exhausted", "window_exhausted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signals := quotaWindowsBaseSignals(acquired)
			signals["X-Codex-Primary-Used-Percent"] = tc.used
			signals["X-Codex-Primary-Reset-At"] = acquired.Add(tc.resetOffset).Format(time.RFC3339Nano)
			w := quotaWindowsFind(t, NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, acquired), acquired.Add(tc.age), QuotaWindowProvenance{}), "x-codex", "primary")
			if w.State != tc.state || w.Reason != tc.reason {
				t.Fatalf("got %+v, want %s/%s", w, tc.state, tc.reason)
			}
			used, _ := strconv.ParseFloat(tc.used, 64)
			quotaWindowsNumber(t, "usage must survive expiry", w.UsedPercent, used)
		})
	}
	q := quotaWindowsAcquired(quotaWindowsBaseSignals(acquired), acquired)
	for _, age := range []time.Duration{300 * time.Second, 300*time.Second + time.Nanosecond} {
		w := quotaWindowsFind(t, NormalizeQuotaWindows("codex", q, acquired.Add(age), QuotaWindowProvenance{}), "x-codex", "secondary")
		if age == 300*time.Second && w.State != "not_applicable" || age > 300*time.Second && w.State != "stale" {
			t.Fatalf("absence did not expire at 300s: %+v", w)
		}
	}
}

func TestNormalizeQuotaWindowsAcquisitionProvenanceIsPerWindow(t *testing.T) {
	now := time.Unix(1793855950, 250000000)
	signals := collectQuotaSignals("claude", quotaWindowsProductionHeaders("claude"))
	q := quotaWindowsAcquired(signals, now)
	old := now.Add(-301 * time.Second)
	for key := range q.SignalObservedAt {
		if strings.Contains(key, "-5h-") {
			q.SignalObservedAt[key] = old
		}
	}
	view := NormalizeQuotaWindows("claude", q, now, QuotaWindowProvenance{Source: "passive_websocket"})
	five, week := quotaWindowsFind(t, view, "unified", "5h"), quotaWindowsFind(t, view, "unified", "7d")
	if five.State != "stale" || week.State != "known" || view.State != "stale" {
		t.Fatalf("latest scalar freshened an old window: %+v", view)
	}
	quotaWindowsNumber(t, "old acquisition", five.ObservedAt, quotaWindowEpoch(old))
	quotaWindowsNumber(t, "new acquisition", week.ObservedAt, quotaWindowEpoch(now))
	later := NormalizeQuotaWindows("claude", q, now.Add(time.Second), QuotaWindowProvenance{Source: "passive_websocket"})
	laterFive := quotaWindowsFind(t, later, "unified", "5h")
	if !reflect.DeepEqual(five.ObservedAt, laterFive.ObservedAt) || !reflect.DeepEqual(five.ResetAt, laterFive.ResetAt) {
		t.Fatal("normalizing at a later now changed original observation/reset")
	}
	quotaWindowsNumber(t, "later age", laterFive.AgeSeconds, 302)
	for _, tc := range []struct {
		name, reason string
		change       func(*QuotaState)
	}{
		{"mixed", "mixed_observation_times", func(q *QuotaState) { q.SignalObservedAt["Anthropic-Ratelimit-Unified-7d-Reset"] = old }},
		{"missing_key", "unverified_observation_time", func(q *QuotaState) { delete(q.SignalObservedAt, "Anthropic-Ratelimit-Unified-7d-Reset") }},
		{"legacy", "unverified_observation_time", func(q *QuotaState) { q.SignalObservedAt = nil }},
		{"zero", "missing_observed_at", func(q *QuotaState) { q.SignalObservedAt = nil; q.ObservedAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := quotaWindowsAcquired(signals, now)
			tc.change(&q)
			w := quotaWindowsFind(t, NormalizeQuotaWindows("claude", q, now, QuotaWindowProvenance{TimestampBasis: "header_acquisition"}), "unified", "7d")
			if w.State != "unknown" || w.Reason != tc.reason || w.TimestampBasis == "header_acquisition" {
				t.Fatalf("bad per-key provenance was accepted: %+v", w)
			}
		})
	}
	// Explicitly unverified historical labels remain unverified even if recent.
	for _, basis := range []string{"request_started", "legacy_result_handled", "unknown", "header_acquisition", "response_acquired", "unsupported"} {
		w := quotaWindowsFind(t, NormalizeQuotaWindows("claude", QuotaState{Signals: signals, ObservedAt: now}, now, QuotaWindowProvenance{Source: "usage_events", TimestampBasis: basis}), "unified", "7d")
		if w.State != "unknown" || w.Reason != "unverified_observation_time" {
			t.Fatalf("legacy basis %q upgraded observation: %+v", basis, w)
		}
	}
}

func TestNormalizeQuotaWindowsOpaqueScopes(t *testing.T) {
	now := time.Unix(1793855950, 0)
	signals := quotaWindowsBaseSignals(now)
	for _, prefix := range []string{"X-Codex-Bengalfox-", "X-Codex-Additional-GPT-5-3-Codex-Spark-", "X-Codex-Code-Review-"} {
		signals[prefix+"Primary-Used-Percent"] = "15"
		signals[prefix+"Primary-Window-Minutes"] = "300"
		signals[prefix+"Primary-Reset-At"] = signals["X-Codex-Primary-Reset-At"]
		signals[prefix+"Secondary-Window-Minutes"] = "0"
	}
	signals["X-Codex-Additional-Incomplete-Primary-Used-Percent"] = "20"
	signals["X-Codex-Additional-GPT-5-3-Codex-Spark-Limit-Name"] = "GPT-5.3-Codex-Spark"
	view := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
	if len(view.Windows) != 10 || view.State != "unknown" {
		t.Fatalf("distinct namespaces were merged or partial group lost: %+v", view)
	}
	for _, key := range []string{"x-codex", "x-codex-bengalfox", "x-codex-additional-gpt-5-3-codex-spark", "x-codex-code-review"} {
		w := quotaWindowsFind(t, view, key, "primary")
		if w.State != "known" || *w.DurationSeconds != 18000 {
			t.Fatalf("incomplete sibling poisoned valid scope %q: %+v", key, w)
		}
	}
	incomplete := quotaWindowsFind(t, view, "x-codex-additional-incomplete", "primary")
	if incomplete.State != "unknown" || incomplete.DurationSeconds != nil {
		t.Fatalf("partial additional group implied applicability: %+v", incomplete)
	}
	claude := collectQuotaSignals("claude", quotaWindowsProductionHeaders("claude"))
	claude["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "0.9"
	claude["Anthropic-Ratelimit-Unified-7d_oi-Reset"] = "1793880000"
	view = NormalizeQuotaWindows("claude", quotaWindowsAcquired(claude, now), now, QuotaWindowProvenance{})
	w := quotaWindowsFind(t, view, "7d_oi", "7d_oi")
	if len(view.Windows) != 3 || w.State != "known" || *w.DurationSeconds != 604800 {
		t.Fatalf("protected opaque namespace lost: %+v", view)
	}
	quotaWindowsNumber(t, "protected usage", w.UsedPercent, 90)
}

func TestNormalizeQuotaWindowsRejectionsAndCreditsAreNotPermission(t *testing.T) {
	now := time.Unix(1793855950, 0)
	signals := quotaWindowsBaseSignals(now)
	signals["X-Codex-Allowed"] = "false"
	signals["X-Codex-Limit-Reached"] = "true"
	signals["X-Codex-Credits-Has-Credits"] = "TrUe"
	signals["X-Codex-Credits-Unlimited"] = "TRUE"
	signals["X-Codex-Credits-Balance"] = "25"
	q := quotaWindowsAcquired(signals, now)
	view := NormalizeQuotaWindows("codex", q, now, QuotaWindowProvenance{})
	w := quotaWindowsFind(t, view, "x-codex", "primary")
	if w.State != "known" || view.LimitSignals["X-Codex-Allowed"] != "false" || view.LimitSignals["X-Codex-Limit-Reached"] != "true" {
		t.Fatalf("unattributed refusal assigned to a window or dropped: %+v", view)
	}
	// The measured window remains known; consumers MUST independently account
	// for the retained aggregate refusal. Known is not admission permission.
	for _, status := range []struct {
		key, value, state string
	}{
		{"X-Codex-Primary-Allowed", "false", "exhausted"},
		{"X-Codex-Primary-Limit-Reached", "true", "exhausted"},
		{"X-Codex-Primary-Allowed", "malformed", "unknown"},
	} {
		signals[status.key] = status.value
		got := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
		window := quotaWindowsFind(t, got, "x-codex", "primary")
		if window.State != status.state {
			t.Fatalf("per-window refusal/status ignored: %+v", window)
		}
		quotaWindowsNumber(t, "refusal does not invent usage", window.UsedPercent, 10)
		delete(signals, status.key)
	}
	signals["X-Codex-Primary-Used-Percent"] = "98"
	view = NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
	if view.State != "exhausted" || view.Credits.Unlimited == nil || !*view.Credits.Unlimited {
		t.Fatalf("credits cleared plan exhaustion: %+v", view)
	}
	quotaWindowsNumber(t, "positive balance", view.Credits.Balance, 25)
	for _, raw := range []string{"", "yes", "1", "false"} {
		signals["X-Codex-Credits-Has-Credits"] = raw
		view = NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
		if raw == "false" {
			if view.Credits.HasCredits == nil || *view.Credits.HasCredits {
				t.Fatal("false credit fact was not preserved")
			}
		} else if view.Credits.HasCredits != nil {
			t.Fatalf("invalid credit boolean %q became known", raw)
		}
	}
	for _, raw := range []string{"-1", "NaN", "Inf", "1e3", "5%"} {
		signals["X-Codex-Credits-Balance"] = raw
		if got := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{}); got.Credits.Balance != nil {
			t.Fatalf("bad balance %q became known: %+v", raw, got.Credits)
		}
	}
	claude := collectQuotaSignals("claude", quotaWindowsProductionHeaders("claude"))
	claude["Anthropic-Ratelimit-Unified-5h-Status"] = "rejected"
	delete(claude, "Anthropic-Ratelimit-Unified-5h-Utilization")
	claude["Anthropic-Ratelimit-Unified-Credits-Can-Purchase"] = "true"
	claude["Anthropic-Ratelimit-Unified-Credits-Has-Payment-Method"] = "TRUE"
	claude["Anthropic-Ratelimit-Unified-Credits-Exhausted-Included"] = "false"
	view = NormalizeQuotaWindows("claude", quotaWindowsAcquired(claude, now), now, QuotaWindowProvenance{})
	w = quotaWindowsFind(t, view, "unified", "5h")
	if w.State != "exhausted" || w.UsedPercent != nil || w.HeadroomPercent != nil || view.State != "exhausted" || view.Credits.CanPurchase == nil || !*view.Credits.CanPurchase || view.Credits.HasPaymentMethod == nil || !*view.Credits.HasPaymentMethod || view.Credits.ExhaustedIncluded == nil || *view.Credits.ExhaustedIncluded {
		t.Fatalf("rejection fabricated utilization or credits cleared exhaustion: %+v", view)
	}
}

func TestNormalizeQuotaWindowsUnknownAndNullableJSON(t *testing.T) {
	now := time.Unix(1793855950, 0)
	for _, tc := range []struct {
		provider string
		signals  map[string]string
		reason   string
	}{
		{"kimi", nil, "unsupported_provider"},
		{"claude", nil, "not_observed"},
		{"codex", map[string]string{}, "not_observed"},
		{"codex", map[string]string{"Request-Id": "excluded"}, "not_observed"},
	} {
		view := NormalizeQuotaWindows(tc.provider, QuotaState{Signals: tc.signals}, now, QuotaWindowProvenance{})
		if view.State != "unknown" || view.Reason != tc.reason || view.Windows == nil || len(view.Windows) != 0 {
			t.Fatalf("empty evidence became capacity: %+v", view)
		}
	}
	for _, provider := range []string{"claude", "codex"} {
		signals := map[string]string{"X-Codex-Plan-Type": "pro"}
		if provider == "claude" {
			signals = map[string]string{"Anthropic-Ratelimit-Unified-Credits-Can-Purchase": "true"}
		}
		view := NormalizeQuotaWindows(provider, quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
		if view.State != "unknown" {
			t.Fatalf("metadata-only observation implied capacity: %+v", view)
		}
		for _, w := range view.Windows {
			if w.State != "unknown" || w.UsedPercent != nil || w.HeadroomPercent != nil {
				t.Fatalf("missing expected window implied free capacity: %+v", w)
			}
		}
	}
	view := NormalizeQuotaWindows("codex", QuotaState{Signals: map[string]string{"X-Codex-Primary-Used-Percent": "0"}}, now, QuotaWindowProvenance{})
	encoded, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Windows []map[string]json.RawMessage `json:"windows"`
		Credits map[string]json.RawMessage   `json:"credits"`
	}
	if errUnmarshal := json.Unmarshal(encoded, &wire); errUnmarshal != nil {
		t.Fatal(errUnmarshal)
	}
	for _, w := range wire.Windows {
		for _, key := range []string{"duration_seconds", "used_percent", "headroom_percent", "reset_at", "observed_at", "age_seconds"} {
			if _, exists := w[key]; !exists {
				t.Fatalf("required nullable numeric key %q omitted: %s", key, encoded)
			}
		}
	}
	for _, key := range []string{"duration_seconds", "used_percent", "headroom_percent", "reset_at", "observed_at", "age_seconds"} {
		if string(wire.Windows[1][key]) != "null" {
			t.Fatalf("missing secondary numeric %q became zero/non-null: %s", key, encoded)
		}
	}
	for _, key := range []string{"has_credits", "unlimited", "balance", "can_purchase", "has_payment_method", "exhausted_included"} {
		if string(wire.Credits[key]) != "null" {
			t.Fatalf("absent credit fact %q isn't explicit null: %s", key, encoded)
		}
	}
}

func TestNormalizeQuotaWindowsDetachedDeterministicAndNativeNeutral(t *testing.T) {
	now := time.Unix(1793855950, 0)
	headers := quotaWindowsProductionHeaders("codex")
	headers["X-Codex-Primary-Used-Percent"] = []string{"99", "9"}
	q := quotaWindowsAcquired(collectQuotaSignals("codex", headers), now)
	before := q.Clone()
	auth := &Auth{Provider: "codex", Quota: q}
	nativeBefore := quotaUsageOf(auth, now)
	view := NormalizeQuotaWindows("codex", q, now, QuotaWindowProvenance{Source: "quota_probe"})
	quotaWindowsNumber(t, "last header wins", quotaWindowsFind(t, view, "x-codex", "primary").UsedPercent, 9)
	for range 5 {
		if again := NormalizeQuotaWindows("codex", q, now, QuotaWindowProvenance{Source: "quota_probe"}); !reflect.DeepEqual(view, again) {
			t.Fatalf("nondeterministic normalization: %+v vs %+v", view, again)
		}
	}
	view.LimitSignals["X-Codex-Allowed"] = "invented"
	view.Windows[0].LimitKey = "modified"
	*view.Windows[0].UsedPercent = 100
	if !reflect.DeepEqual(before, q) || !reflect.DeepEqual(nativeBefore, quotaUsageOf(auth, now)) {
		t.Fatal("normalizer changed input or native selector behavior")
	}
	for _, tc := range []struct {
		states []string
		want   string
	}{
		{[]string{"not_applicable", "not_applicable"}, "not_applicable"},
		{[]string{"known", "not_applicable"}, "known"},
		{[]string{"known", "stale"}, "stale"},
		{[]string{"known", "unknown", "stale"}, "unknown"},
		{[]string{"exhausted", "unknown", "stale"}, "exhausted"},
		{nil, "unknown"},
	} {
		windows := make([]QuotaWindowView, 0, len(tc.states))
		for _, state := range tc.states {
			windows = append(windows, QuotaWindowView{State: state})
		}
		if got := quotaWindowsState(windows); got != tc.want {
			t.Fatalf("state reduction %v = %s, want %s", tc.states, got, tc.want)
		}
	}
}
