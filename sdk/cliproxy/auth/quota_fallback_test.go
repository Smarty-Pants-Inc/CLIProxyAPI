package auth

import (
	"math"
	"strings"
	"testing"
	"time"
)

func TestParseCodexQuotaUsedPercent(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want float64
	}{
		{raw: "0", want: 0},
		{raw: ".5", want: 0.5},
		{raw: "12.125", want: 12.125},
		{raw: "100", want: 100},
		{raw: "100.25", want: 100.25},
		{raw: " 101.5 \t", want: 101.5},
		{raw: strings.Repeat("9", 72), want: 1e72},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := ParseCodexQuotaUsedPercent(tc.raw)
			if !ok || math.Abs(got-tc.want) > 1e-12 {
				t.Fatalf("ParseCodexQuotaUsedPercent(%q) = %v, %v; want %v, true", tc.raw, got, ok, tc.want)
			}
		})
	}

	for _, raw := range []string{
		"", " ", "-0", "-1", "+1", "NaN", "Inf", "+Inf", "-Inf", "Infinity",
		"1e2", "100%", "1.2.3",
	} {
		t.Run("reject/"+raw, func(t *testing.T) {
			if got, ok := ParseCodexQuotaUsedPercent(raw); ok {
				t.Fatalf("ParseCodexQuotaUsedPercent(%q) = %v, true; want invalid", raw, got)
			}
		})
	}

	t.Run("reject/overflow", func(t *testing.T) {
		raw := strings.Repeat("9", 400)
		if got, ok := ParseCodexQuotaUsedPercent(raw); ok {
			t.Fatalf("ParseCodexQuotaUsedPercent(400-digit decimal) = %v, true; want overflow rejected", got)
		}
	})
}

func TestCodexFallbackPercentParserDoesNotChangeWindowProjectionCap(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	signals := quotaWindowsBaseSignals(now)
	signals["X-Codex-Primary-Used-Percent"] = "100.25"
	view := NormalizeQuotaWindows("codex", quotaWindowsAcquired(signals, now), now, QuotaWindowProvenance{})
	primary := quotaWindowsFind(t, view, "x-codex", "primary")
	if primary.State != "unknown" || primary.Reason != "invalid_utilization" || primary.UsedPercent != nil || primary.HeadroomPercent != nil {
		t.Fatalf("fallback parser changed native window normalization above 100: %+v", primary)
	}
}
