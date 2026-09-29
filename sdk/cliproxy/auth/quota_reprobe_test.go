package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A weekly-reset 429 (upstream reset_seconds ~94 h) must not hold a credential
// for days: after a top-up the proxy kept refusing with model_cooldown until a
// restart. The hold now lasts at most quotaReprobeInterval, then the account is
// tried again.
func TestManager_MarkResult_WeeklyRetryAfterIsReprobedHourly(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	for _, credentialScope := range []bool{false, true} {
		m, auth := newCooldownMonotonicManager(t, "gpt-reprobe-a", "gpt-reprobe-b")
		weekly := 338119 * time.Second
		before := time.Now()
		m.MarkResult(context.Background(), Result{
			AuthID: auth.ID, Provider: auth.Provider, Model: "gpt-reprobe-a",
			Success: false, RetryAfter: &weekly, CredentialScope: credentialScope,
			Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"},
		})
		updated, _ := m.GetByID(auth.ID)

		if blocked, _, _ := isAuthBlockedForModel(updated, "gpt-reprobe-a", before.Add(30*time.Minute)); !blocked {
			t.Fatalf("scope=%v: account should stay held within the re-probe interval", credentialScope)
		}
		if blocked, _, next := isAuthBlockedForModel(updated, "gpt-reprobe-a", before.Add(quotaReprobeInterval+time.Minute)); blocked {
			t.Fatalf("scope=%v: account still held after the re-probe interval, until %v", credentialScope, next.Sub(before))
		}
		if credentialScope && updated.NextRetryAfter.After(before.Add(quotaReprobeInterval+time.Minute)) {
			t.Fatalf("credential hold %v exceeds the re-probe interval", updated.NextRetryAfter.Sub(before))
		}
	}
}

func TestQuotaRetryAfterCooldown_Bounds(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{
		{0, minQuotaCooldownFloor},
		{5 * time.Minute, 5 * time.Minute},
		{94 * time.Hour, quotaReprobeInterval},
	} {
		if got := quotaRetryAfterCooldown(tc.in); got != tc.want {
			t.Fatalf("quotaRetryAfterCooldown(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A passive snapshot at 100% with a weekly reset skips the account only while it
// is fresh; after quotaReprobeInterval selection tries the account again.
func TestQuotaExhausted_StaleSnapshotIsReprobed(t *testing.T) {
	now := time.Now()
	weeklyReset := now.Add(94 * time.Hour)
	if !quotaExhausted(claudeQuotaAuth("fresh", 0.10, 1.00, weeklyReset, now.Add(-10*time.Minute)), now) {
		t.Fatal("fresh exhausted snapshot should skip the account")
	}
	if quotaExhausted(claudeQuotaAuth("stale", 0.10, 1.00, weeklyReset, now.Add(-quotaReprobeInterval-time.Minute)), now) {
		t.Fatal("snapshot older than the re-probe interval should not skip the account")
	}
}
