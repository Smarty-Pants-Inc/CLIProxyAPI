package auth

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func claudeQuotaAuth(id string, util5h, util7d float64, reset time.Time, observedAt time.Time) *Auth {
	resetUnix := strconv.FormatInt(reset.Unix(), 10)
	return &Auth{ID: id, Provider: "claude", Quota: QuotaState{ObservedAt: observedAt, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": strconv.FormatFloat(util5h, 'f', 2, 64),
		"Anthropic-Ratelimit-Unified-5h-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-5h-Reset":       resetUnix,
		"Anthropic-Ratelimit-Unified-7d-Utilization": strconv.FormatFloat(util7d, 'f', 2, 64),
		"Anthropic-Ratelimit-Unified-7d-Status":      "allowed",
		"Anthropic-Ratelimit-Unified-7d-Reset":       resetUnix,
	}}}
}

func TestQuotaUsageOf_Windows(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Minute)
	cases := []struct {
		name          string
		auth          *Auth
		wantExhausted bool
		wantUtil      float64
	}{
		{"no signals", &Auth{ID: "a"}, false, 0},
		{"claude 5h at 98%", claudeQuotaAuth("a", 0.98, 0.10, future, now), true, 0.98},
		{"claude 5h at 97%", claudeQuotaAuth("a", 0.97, 0.10, future, now), false, 0.97},
		{"claude weekly at 99%", claudeQuotaAuth("a", 0.10, 0.99, future, now), true, 0.99},
		{"claude window reset passed", claudeQuotaAuth("a", 1.00, 1.00, past, now.Add(-2*time.Hour)), false, 0},
		{"claude 7d rejected below threshold", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-7d-Utilization": "0.50",
			"Anthropic-Ratelimit-Unified-7d-Status":      "rejected",
			"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(future.Unix(), 10),
		}}}, true, 1},
		{"claude 98% without reset is not skipped", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization": "0.99",
		}}}, false, 0.99},
		{"codex primary 98 via reset-after", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":        "98",
			"X-Codex-Primary-Reset-After-Seconds": "600",
		}}}, true, 0.98},
		{"codex primary reset-after elapsed", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now.Add(-20 * time.Minute), Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":        "100",
			"X-Codex-Primary-Reset-After-Seconds": "600",
		}}}, false, 0},
		{"codex secondary 99 via reset-at", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent":   "5",
			"X-Codex-Primary-Reset-At":       strconv.FormatInt(future.Unix(), 10),
			"X-Codex-Secondary-Used-Percent": "99",
			"X-Codex-Secondary-Reset-At":     strconv.FormatInt(future.Unix(), 10),
		}}}, true, 0.99},
		{"codex limit reached", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Limit-Reached":        "true",
			"X-Codex-Primary-Used-Percent": "40",
			"X-Codex-Primary-Reset-At":     strconv.FormatInt(future.Unix(), 10),
		}}}, true, 1},
		{"codex 97", &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
			"X-Codex-Primary-Used-Percent": "97",
			"X-Codex-Primary-Reset-At":     strconv.FormatInt(future.Unix(), 10),
		}}}, false, 0.97},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := quotaUsageOf(tc.auth, now)
			if got.exhausted != tc.wantExhausted || got.utilization != tc.wantUtil {
				t.Fatalf("quotaUsageOf = %+v, want exhausted=%v utilization=%v", got, tc.wantExhausted, tc.wantUtil)
			}
		})
	}
}

func TestSkipQuotaExhausted_AllExhaustedKeepsLeastUtilized(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	auths := []*Auth{
		claudeQuotaAuth("a", 1.00, 0.20, future, now),
		claudeQuotaAuth("b", 0.98, 0.20, future, now),
		claudeQuotaAuth("c", 0.99, 0.20, future, now),
	}
	got := skipQuotaExhausted(auths, now)
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("skipQuotaExhausted = %v, want [b]", authIDs(got))
	}
	auths = append(auths, claudeQuotaAuth("d", 0.50, 0.50, future, now))
	if got = skipQuotaExhausted(auths, now); len(got) != 1 || got[0].ID != "d" {
		t.Fatalf("skipQuotaExhausted = %v, want [d]", authIDs(got))
	}
}

func authIDs(auths []*Auth) []string {
	ids := make([]string, 0, len(auths))
	for _, a := range auths {
		ids = append(ids, a.ID)
	}
	return ids
}

var quotaSkipSelectors = map[string]Selector{
	"round-robin":          &RoundRobinSelector{},
	"fill-first":           &FillFirstSelector{},
	"weighted-round-robin": &WeightedRoundRobinSelector{},
}

// Reproduces 2026-09-28 04:33-04:37Z: round-robin tried 16 exhausted accounts
// once each. With the skip, every pick lands on the one account with headroom.
func TestSchedulerPick_SkipsQuotaExhaustedAccounts(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			auths := make([]*Auth, 0, 17)
			for i := 0; i < 16; i++ {
				auths = append(auths, claudeQuotaAuth(fmt.Sprintf("a%02d", i), 0.98+float64(i%3)/100, 0.3, future, now))
			}
			auths = append(auths, claudeQuotaAuth("z-fresh", 0.40, 0.40, future, now))
			scheduler := newSchedulerForTest(selector, auths...)
			for i := 0; i < 32; i++ {
				got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil || got.ID != "z-fresh" {
					t.Fatalf("pick #%d = %v, %v; want z-fresh", i, got, errPick)
				}
			}
		})
	}
}

func TestSchedulerPick_AllExhaustedFallsBackToLeastUtilized(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			scheduler := newSchedulerForTest(selector,
				claudeQuotaAuth("a", 1.00, 0.30, future, now),
				claudeQuotaAuth("b", 0.30, 0.985, future, now),
				claudeQuotaAuth("c", 0.99, 0.30, future, now),
			)
			for i := 0; i < 4; i++ {
				got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil || got.ID != "b" {
					t.Fatalf("pick #%d = %v, %v; want b (least utilized)", i, got, errPick)
				}
			}
			// Once the least-utilized one is tried, the next least is offered: never zero candidates.
			got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, map[string]struct{}{"b": {}})
			if errPick != nil || got == nil || got.ID != "c" {
				t.Fatalf("pick after b tried = %v, %v; want c", got, errPick)
			}
		})
	}
}

func TestSchedulerPick_ExhaustedAccountEligibleAfterReset(t *testing.T) {
	now := time.Now()
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			// "a-reset" sorts first; it was exhausted but its window reset already.
			scheduler := newSchedulerForTest(selector,
				claudeQuotaAuth("a-reset", 1.00, 1.00, now.Add(-time.Second), now.Add(-5*time.Hour)),
				claudeQuotaAuth("b-fresh", 0.10, 0.10, now.Add(time.Hour), now),
			)
			seen := map[string]int{}
			for i := 0; i < 4; i++ {
				got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil {
					t.Fatalf("pick #%d error = %v", i, errPick)
				}
				seen[got.ID]++
			}
			if seen["a-reset"] == 0 {
				t.Fatalf("account whose window reset was never picked: %v", seen)
			}
		})
	}
}

func TestSchedulerPick_ExhaustedAccountReturnsWhenResetPasses(t *testing.T) {
	now := time.Now()
	reset := now.Add(1500 * time.Millisecond)
	scheduler := newSchedulerForTest(&FillFirstSelector{},
		claudeQuotaAuth("a", 0.99, 0.10, reset, now),
		claudeQuotaAuth("b", 0.20, 0.10, now.Add(time.Hour), now),
	)
	got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil || got == nil || got.ID != "b" {
		t.Fatalf("before reset pick = %v, %v; want b", got, errPick)
	}
	time.Sleep(time.Until(reset) + 600*time.Millisecond)
	got, errPick = scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil || got == nil || got.ID != "a" {
		t.Fatalf("after reset fill-first pick = %v, %v; want a", got, errPick)
	}
}

func TestSchedulerPickMixed_SkipsQuotaExhaustedAccounts(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	codexFull := &Auth{ID: "codex-full", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "100",
		"X-Codex-Primary-Reset-At":     strconv.FormatInt(future.Unix(), 10),
	}}}
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			scheduler := newSchedulerForTest(selector,
				claudeQuotaAuth("claude-full", 0.99, 0.2, future, now),
				codexFull,
				claudeQuotaAuth("claude-ok", 0.2, 0.2, future, now),
			)
			for i := 0; i < 6; i++ {
				got, provider, errPick := scheduler.pickMixed(context.Background(), []string{"claude", "codex"}, "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil || got.ID != "claude-ok" || provider != "claude" {
					t.Fatalf("pick #%d = %v/%s, %v; want claude-ok", i, got, provider, errPick)
				}
			}
			got, _, errPick := scheduler.pickMixed(context.Background(), []string{"claude", "codex"}, "", cliproxyexecutor.Options{}, map[string]struct{}{"claude-ok": {}})
			if errPick != nil || got == nil || got.ID != "claude-full" {
				t.Fatalf("all exhausted pick = %v, %v; want claude-full (least utilized)", got, errPick)
			}
		})
	}
}

// The legacy selector path (plugin schedulers, session affinity, custom
// selectors) filters through availableAuthsForRouteModel and getAvailableAuths.
func TestLegacySelectorPath_SkipsQuotaExhaustedAccounts(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	full := claudeQuotaAuth("a-full", 1.0, 0.2, future, now)
	full.Attributes = map[string]string{"priority": "10"}
	ok := claudeQuotaAuth("b-ok", 0.2, 0.2, future, now)
	manager := NewManager(nil, nil, nil)
	available, errAvailable := manager.availableAuthsForRouteModel([]*Auth{full, ok}, "claude", "", now)
	if errAvailable != nil || len(available) != 1 || available[0].ID != "b-ok" {
		t.Fatalf("availableAuthsForRouteModel = %v, %v; want [b-ok] (exhausted top tier falls through)", authIDs(available), errAvailable)
	}
	for name, selector := range quotaSkipSelectors {
		for i := 0; i < 3; i++ {
			got, errPick := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, []*Auth{full, ok})
			if errPick != nil || got == nil || got.ID != "b-ok" {
				t.Fatalf("%s Pick #%d = %v, %v; want b-ok", name, i, got, errPick)
			}
		}
	}
	allFull := []*Auth{full, claudeQuotaAuth("c-full", 0.98, 0.2, future, now)}
	available, errAvailable = manager.availableAuthsForRouteModel(allFull, "claude", "", now)
	if errAvailable != nil || len(available) != 1 || available[0].ID != "c-full" {
		t.Fatalf("all exhausted = %v, %v; want [c-full]", authIDs(available), errAvailable)
	}
}

// smarty-dev#3200: a Codex account whose plan window is full but which still has a credit
// grant keeps serving, so it stays ahead of a lower-priority fallback credential; once the
// credits are gone the fallback tier serves.
func TestQuotaUsageOf_CodexCreditsKeepFullAccountEligible(t *testing.T) {
	now := time.Now()
	reset := strconv.FormatInt(now.Add(time.Hour).Unix(), 10)
	codex := func(extra map[string]string) *Auth {
		signals := map[string]string{"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-At": reset}
		for k, v := range extra {
			signals[k] = v
		}
		return &Auth{ID: "codex", Provider: "codex", Attributes: map[string]string{"priority": "10"}, Quota: QuotaState{ObservedAt: now, Signals: signals}}
	}
	cases := []struct {
		name          string
		auth          *Auth
		wantExhausted bool
	}{
		{"no credit signals", codex(nil), true},
		{"credits with balance", codex(map[string]string{"X-Codex-Credits-Has-Credits": "True", "X-Codex-Credits-Balance": "59474.06"}), false},
		{"credits without balance header", codex(map[string]string{"X-Codex-Credits-Has-Credits": "true"}), false},
		{"credits with zero balance", codex(map[string]string{"X-Codex-Credits-Has-Credits": "True", "X-Codex-Credits-Balance": "0"}), true},
		{"no credits", codex(map[string]string{"X-Codex-Credits-Has-Credits": "False", "X-Codex-Credits-Balance": "0"}), true},
		{"unlimited credits", codex(map[string]string{"X-Codex-Credits-Unlimited": "True"}), false},
	}
	fallback := claudeQuotaAuth("claude", 0.2, 0.2, now.Add(time.Hour), now)
	manager := NewManager(nil, nil, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quotaUsageOf(tc.auth, now); got.exhausted != tc.wantExhausted || got.utilization != 1 {
				t.Fatalf("quotaUsageOf = %+v, want exhausted=%v utilization=1", got, tc.wantExhausted)
			}
			want := "codex"
			if tc.wantExhausted {
				want = "claude"
			}
			available, err := manager.availableAuthsForRouteModel([]*Auth{tc.auth, fallback}, "mixed", "", now)
			if err != nil || len(available) != 1 || available[0].ID != want {
				t.Fatalf("available = %v, %v; want [%s]", authIDs(available), err, want)
			}
		})
	}
}

func TestQuotaUsageOf_OutOfRangeResetNeverSkips(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cases := map[string]map[string]string{
		"reset-after 1e30":         {"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-After-Seconds": "1e30"},
		"reset-after 31 days":      {"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-After-Seconds": "2678400"},
		"codex reset-at 1e300":     {"X-Codex-Secondary-Used-Percent": "100", "X-Codex-Secondary-Reset-At": "1e300"},
		"codex reset-at +60 days":  {"X-Codex-Secondary-Used-Percent": "100", "X-Codex-Secondary-Reset-At": "1805184000"},
		"claude reset 9e18":        {"Anthropic-Ratelimit-Unified-5h-Utilization": "1", "Anthropic-Ratelimit-Unified-5h-Reset": "9e18"},
		"codex limit reached 1e30": {"X-Codex-Limit-Reached": "true", "X-Codex-Primary-Reset-After-Seconds": "1e30"},
	}
	for name, signals := range cases {
		auth := &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: signals}}
		if quotaExhausted(auth, now) {
			t.Errorf("%s: out-of-range reset caused a skip", name)
		}
	}
	// In-range values at the horizon still skip.
	inRange := &Auth{ID: "a", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-After-Seconds": "604800"}}}
	if !quotaExhausted(inRange, now) {
		t.Error("weekly reset-after should still skip")
	}
}

// Codex reports limit_reached once for the whole rate-limit object. It must
// expire with the window that actually hit the limit, not with the weekly one.
func TestQuotaUsageOf_CodexLimitReachedExpiresWithLimitingWindow(t *testing.T) {
	observed := time.Unix(1_800_000_000, 0)
	primaryReset := observed.Add(time.Hour)
	secondaryReset := observed.Add(7 * 24 * time.Hour)
	auth := &Auth{ID: "a", Provider: "codex", Quota: QuotaState{ObservedAt: observed, Signals: map[string]string{
		"X-Codex-Limit-Reached":          "true",
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Reset-At":       strconv.FormatInt(primaryReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent": "20",
		"X-Codex-Secondary-Reset-At":     strconv.FormatInt(secondaryReset.Unix(), 10),
	}}}
	if got := quotaUsageOf(auth, observed.Add(time.Minute)); !got.exhausted || got.utilization != 1 {
		t.Fatalf("before primary reset = %+v, want exhausted utilization=1", got)
	}
	if got := quotaUsageOf(auth, observed.Add(2*time.Hour)); got.exhausted || got.utilization != 0.20 {
		t.Fatalf("after primary reset = %+v, want not exhausted utilization=0.20", got)
	}

	// The weekly window hit the limit: the skip lasts until the weekly reset.
	weekly := &Auth{ID: "w", Provider: "codex", Quota: QuotaState{ObservedAt: observed, Signals: map[string]string{
		"X-Codex-Limit-Reached":          "true",
		"X-Codex-Primary-Used-Percent":   "30",
		"X-Codex-Primary-Reset-At":       strconv.FormatInt(primaryReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent": "100",
		"X-Codex-Secondary-Reset-At":     strconv.FormatInt(secondaryReset.Unix(), 10),
	}}}
	if got := quotaUsageOf(weekly, observed.Add(2*time.Hour)); !got.exhausted {
		t.Fatalf("weekly limit after primary reset = %+v, want exhausted", got)
	}
	if got := quotaUsageOf(weekly, secondaryReset.Add(time.Second)); got.exhausted {
		t.Fatalf("weekly limit after weekly reset = %+v, want eligible", got)
	}

	// No window is at the threshold: the flag is tied to the earliest reset
	// (bounded reconsideration), never to the unrelated weekly reset.
	ambiguous := &Auth{ID: "u", Provider: "codex", Quota: QuotaState{ObservedAt: observed, Signals: map[string]string{
		"X-Codex-Limit-Reached":          "true",
		"X-Codex-Primary-Used-Percent":   "90",
		"X-Codex-Primary-Reset-At":       strconv.FormatInt(primaryReset.Unix(), 10),
		"X-Codex-Secondary-Used-Percent": "20",
		"X-Codex-Secondary-Reset-At":     strconv.FormatInt(secondaryReset.Unix(), 10),
	}}}
	if got := quotaUsageOf(ambiguous, observed.Add(time.Minute)); !got.exhausted {
		t.Fatalf("ambiguous before earliest reset = %+v, want exhausted", got)
	}
	if got := quotaUsageOf(ambiguous, observed.Add(2*time.Hour)); got.exhausted {
		t.Fatalf("ambiguous after earliest reset = %+v, want eligible", got)
	}
}

// A recovered Codex account (its 5h limit reset; weekly at 20%) is offered
// again even though another account with headroom exists.
func TestSchedulerPick_CodexRecoveredAfterPrimaryResetIsEligible(t *testing.T) {
	now := time.Now()
	recovered := &Auth{ID: "a-recovered", Provider: "codex", Quota: QuotaState{ObservedAt: now.Add(-2 * time.Hour), Signals: map[string]string{
		"X-Codex-Limit-Reached":          "true",
		"X-Codex-Primary-Used-Percent":   "100",
		"X-Codex-Primary-Reset-At":       strconv.FormatInt(now.Add(-time.Hour).Unix(), 10),
		"X-Codex-Secondary-Used-Percent": "20",
		"X-Codex-Secondary-Reset-At":     strconv.FormatInt(now.Add(5*24*time.Hour).Unix(), 10),
	}}}
	fresh := &Auth{ID: "b-fresh", Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Primary-Used-Percent": "10",
		"X-Codex-Primary-Reset-At":     strconv.FormatInt(now.Add(time.Hour).Unix(), 10),
	}}}
	for name, selector := range quotaSkipSelectors {
		t.Run(name, func(t *testing.T) {
			scheduler := newSchedulerForTest(selector, recovered, fresh)
			seen := map[string]int{}
			for i := 0; i < 4; i++ {
				got, errPick := scheduler.pickSingle(context.Background(), "codex", "", cliproxyexecutor.Options{}, nil)
				if errPick != nil || got == nil {
					t.Fatalf("pick #%d error = %v", i, errPick)
				}
				seen[got.ID]++
			}
			if seen["a-recovered"] == 0 {
				t.Fatalf("recovered account never picked: %v", seen)
			}
		})
	}
}

// The quota pre-skip must run over the weighted selector's own candidates: a
// zero-weight credential can neither survive the skip alone nor be the
// least-utilized fallback. Covers SelectAuth, plugin fallback, weighted session
// affinity (with and without a session) and mixed-provider selection.
func TestManagerWeightedSelection_ZeroWeightDoesNotHideQuotaFallback(t *testing.T) {
	now := time.Now()
	future := now.Add(time.Hour)
	zeroUnknown := func() *Auth {
		return &Auth{ID: "a-zero", Provider: "claude", Attributes: map[string]string{AttributeWeight: "0"}}
	}
	zeroExhausted := func() *Auth {
		auth := claudeQuotaAuth("a-zero", 0.985, 0.2, future, now)
		auth.Attributes = map[string]string{AttributeWeight: "0"}
		return auth
	}
	busy := func() *Auth {
		auth := claudeQuotaAuth("b-busy", 0.99, 0.2, future, now)
		auth.Attributes = map[string]string{AttributeWeight: "1"}
		return auth
	}
	selectors := map[string]func() Selector{
		"weighted":          func() Selector { return &WeightedRoundRobinSelector{} },
		"weighted-affinity": func() Selector { return NewSessionAffinitySelector(&WeightedRoundRobinSelector{}) },
	}
	zeros := map[string]func() *Auth{"unknown-quota": zeroUnknown, "exhausted-lower": zeroExhausted}
	for selectorName, newSelector := range selectors {
		for zeroName, newZero := range zeros {
			for _, plugin := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/plugin=%v", selectorName, zeroName, plugin)
				t.Run(name, func(t *testing.T) {
					manager := NewManager(nil, newSelector(), nil)
					manager.executors["claude"] = schedulerTestExecutor{}
					manager.executors["codex"] = schedulerTestExecutor{}
					var pluginScheduler *fakePluginScheduler
					if plugin {
						pluginScheduler = &fakePluginScheduler{}
						manager.SetPluginScheduler(pluginScheduler)
					}
					for _, auth := range []*Auth{newZero(), busy()} {
						if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
							t.Fatalf("Register(%s) error = %v", auth.ID, errRegister)
						}
					}
					sessionOpts := cliproxyexecutor.Options{Headers: http.Header{"Session_id": []string{"quota-session"}}}
					for i, opts := range []cliproxyexecutor.Options{{}, sessionOpts, sessionOpts} {
						got, errPick := manager.SelectAuth(context.Background(), "claude", "", opts)
						if errPick != nil || got == nil || got.ID != "b-busy" {
							t.Fatalf("SelectAuth #%d = %v, %v; want b-busy", i, got, errPick)
						}
						mixed, _, provider, errMixed := manager.pickNextMixedLegacy(context.Background(), []string{"claude", "codex"}, "", opts, nil)
						if errMixed != nil || mixed == nil || mixed.ID != "b-busy" || provider != "claude" {
							t.Fatalf("mixed #%d = %v/%s, %v; want b-busy", i, mixed, provider, errMixed)
						}
					}
					if plugin {
						// The unhandled plugin still saw the zero-weight credential.
						if pluginScheduler.calls == 0 || len(pluginScheduler.requests[0].Candidates) != 1 || pluginScheduler.requests[0].Candidates[0].ID != "a-zero" {
							t.Fatalf("plugin candidates = %+v, want the plugin's own unweighted quota view", pluginScheduler.requests)
						}
					}
				})
			}
		}
	}
}
