package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// codexWeeklyFullAuth reproduces the smarty-dev#6379 field reading: the weekly
// primary window at 100% with its reset still days ahead.
func codexWeeklyFullAuth(id string, now, observedAt time.Time) *Auth {
	return &Auth{ID: id, Provider: "codex", Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Window-Minutes": "10080",
		"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(4*24*time.Hour).Unix(), 10),
	}}}
}

func codexHeadroomAuth(id string, now time.Time) *Auth {
	return &Auth{ID: id, Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "10",
		"X-Codex-Primary-Reset-At":     strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
	}}}
}

// (a) A 100% reading with a future reset observed 7 h ago is older than the
// default 6 h bound: it is unknown, so the seat is eligible again.
func TestQuotaReadingAge_StaleExhaustedReadingIsEligible(t *testing.T) {
	now := time.Now()
	stale := codexWeeklyFullAuth("a-stale", now, now.Add(-7*time.Hour))
	if quotaExhausted(stale, now) {
		t.Fatal("7h-old exhausted reading still skips the seat")
	}
	if got := authIDs(skipQuotaExhausted([]*Auth{stale, codexHeadroomAuth("b-fresh", now)}, now)); len(got) != 2 {
		t.Fatalf("skipQuotaExhausted = %v, want both seats", got)
	}
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			scheduler := newSchedulerForTest(selector, codexWeeklyFullAuth("a-stale", now, now.Add(-7*time.Hour)), codexHeadroomAuth("b-fresh", now))
			seen := map[string]int{}
			for i := 0; i < 4; i++ {
				got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil {
					t.Fatalf("pick #%d error = %v", i, errPick)
				}
				seen[got.ID]++
			}
			if seen["a-stale"] == 0 {
				t.Fatalf("stale seat never picked: %v", seen)
			}
		})
	}
}

// (b) The same reading observed 1 h ago is within the bound and still skips.
func TestQuotaReadingAge_RecentExhaustedReadingStillSkipped(t *testing.T) {
	now := time.Now()
	recent := codexWeeklyFullAuth("a-recent", now, now.Add(-time.Hour))
	if !quotaExhausted(recent, now) {
		t.Fatal("1h-old exhausted reading no longer skips the seat")
	}
	if got := authIDs(skipQuotaExhausted([]*Auth{recent, codexHeadroomAuth("b-fresh", now)}, now)); len(got) != 1 || got[0] != "b-fresh" {
		t.Fatalf("skipQuotaExhausted = %v, want [b-fresh]", got)
	}
}

// (c) A bound of 0 restores the old behaviour: the 7h-old reading still skips
// until its recorded reset passes; nil restores the default bound.
func TestQuotaReadingAge_ZeroBoundNeverExpires(t *testing.T) {
	t.Cleanup(func() { SetQuotaReadingMaxAgeSeconds(nil) })
	now := time.Now()
	stale := codexWeeklyFullAuth("a-stale", now, now.Add(-7*time.Hour))
	zero := 0
	SetQuotaReadingMaxAgeSeconds(&zero)
	if !quotaExhausted(stale, now) {
		t.Fatal("bound 0: 7h-old exhausted reading no longer skips the seat")
	}
	if quotaExhausted(stale, now.Add(5*24*time.Hour)) {
		t.Fatal("bound 0: reading still skips after its reset passed")
	}
	SetQuotaReadingMaxAgeSeconds(nil)
	if quotaExhausted(stale, now) {
		t.Fatal("nil bound did not restore the default 6h expiry")
	}
	hour := 3600
	SetQuotaReadingMaxAgeSeconds(&hour)
	if quotaExhausted(codexWeeklyFullAuth("b", now, now.Add(-2*time.Hour)), now) {
		t.Fatal("configured 1h bound did not expire a 2h-old reading")
	}
}
