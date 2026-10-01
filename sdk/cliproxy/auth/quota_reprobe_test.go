package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
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

// A cooldown file written before the re-probe bound holds a weekly 429 for
// ~94 h. After an upgrade, restore must not keep the account out of selection
// longer than one re-probe interval from when the hold was set, at auth level
// and at model level (Astra CLIProxyAPI#21 R1 P2).
func TestRestoreCooldownStates_OldMultiDayQuotaHoldIsReprobed(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	const model = "gpt-reprobe-restore"
	for _, tc := range []struct {
		name, model, reason string
	}{
		{"auth-level", "", "credential_quota"},
		{"model-level", model, "quota"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			weekly := now.Add(94 * time.Hour).Truncate(time.Second)
			// Old-format record, as the previous release persisted it.
			oldRecord := func(id string, setAt time.Time) CooldownStateRecord {
				raw := fmt.Sprintf(`{"provider":"claude","auth_id":%q,"model":%q,"status":"cooling",`+
					`"next_retry_after":%q,"reason":%q,"quota":{"exceeded":true,"reason":%q,"next_recover_at":%q,"backoff_level":0},`+
					`"last_error":{"message":"usage_limit_reached","http_status":429},"updated_at":%q}`,
					id, tc.model, weekly.Format(time.RFC3339), tc.reason, tc.reason, weekly.Format(time.RFC3339), setAt.Format(time.RFC3339Nano))
				var record CooldownStateRecord
				if err := json.Unmarshal([]byte(raw), &record); err != nil {
					t.Fatal(err)
				}
				return record
			}
			m := NewManager(nil, nil, nil)
			m.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
			stale := &Auth{ID: "reprobe-restore-stale-" + tc.name, Provider: "claude"}
			recent := &Auth{ID: "reprobe-restore-recent-" + tc.name, Provider: "claude"}
			for _, a := range []*Auth{stale, recent} {
				registry.GetGlobalRegistry().RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: model, Created: now.Unix()}})
				id := a.ID
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			store := &mockCooldownStateStore{records: []CooldownStateRecord{
				oldRecord(stale.ID, now.Add(-quotaReprobeInterval-time.Minute)),
				oldRecord(recent.ID, now.Add(-10*time.Minute)),
			}}
			m.SetCooldownStateStore(store)
			for _, a := range []*Auth{stale, recent} {
				if _, err := m.Register(WithSkipPersist(context.Background()), a); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.RestoreCooldownStates(context.Background()); err != nil {
				t.Fatal(err)
			}

			// Held within the interval: the recent hold still applies.
			got, _ := m.GetByID(recent.ID)
			if blocked, _, _ := isAuthBlockedForModel(got, model, time.Now()); !blocked {
				t.Fatal("hold set 10 min ago should still apply after restore")
			}
			limit := now.Add(-10 * time.Minute).Add(quotaReprobeInterval + time.Second)
			if blocked, _, next := isAuthBlockedForModel(got, model, limit); blocked {
				t.Fatalf("restored hold lasts %v past restore, want <= re-probe interval from when it was set", next.Sub(now))
			}
			// Actual selection: the hold set over one interval ago is eligible now,
			// the recent one is not picked.
			for i := 0; i < 4; i++ {
				picked, _, err := m.pickNext(context.Background(), "claude", model, cliproxyexecutor.Options{}, nil)
				if err != nil {
					t.Fatalf("pickNext: %v (old multi-day hold still blocks selection)", err)
				}
				if picked.ID != stale.ID {
					t.Fatalf("pickNext = %s, want the re-probed %s", picked.ID, stale.ID)
				}
			}
		})
	}
}

// A propagated credential quota must not turn an independent model-support
// deadline into a quota deadline when the persisted state is restored.
func TestRestoreCooldownStates_CredentialQuotaPreservesIndependentSupportHold(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	for _, tc := range []struct {
		name      string
		legacyAge time.Duration
	}{
		{name: "current"},
		{name: "legacy recent quota", legacyAge: 10 * time.Minute},
		{name: "legacy expired quota", legacyAge: quotaReprobeInterval + time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const modelA = "gpt-restore-support-a"
			const modelB = "gpt-restore-support-b"
			manager, auth := newCooldownMonotonicManager(t, modelA, modelB)
			store := &recordingCooldownStateStore{}
			manager.SetCooldownStateStore(store)
			manager.MarkResult(context.Background(), Result{
				AuthID: auth.ID, Provider: auth.Provider, Model: modelA,
				Error: &Error{HTTPStatus: http.StatusNotFound, Message: "model not found"},
			})
			beforeQuota, _ := manager.GetByID(auth.ID)
			wantSupportDeadline := beforeQuota.ModelStates[modelA].NextRetryAfter
			weekly := 94 * time.Hour
			manager.MarkResult(context.Background(), Result{
				AuthID: auth.ID, Provider: auth.Provider, Model: modelB,
				CredentialScope: true, RetryAfter: &weekly,
				Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"},
			})
			records := store.savedRecords()
			var supportRecord *CooldownStateRecord
			for i := range records {
				if records[i].Model == modelA {
					supportRecord = &records[i]
				}
			}
			if supportRecord == nil || supportRecord.LastError == nil || supportRecord.LastError.HTTPStatus != http.StatusNotFound ||
				!supportRecord.NextRetryAfter.Equal(wantSupportDeadline) || !supportRecord.Quota.Exceeded ||
				!supportRecord.Quota.NextRecoverAt.Before(wantSupportDeadline) {
				t.Fatalf("persisted support/quota precondition failed: %+v", supportRecord)
			}
			now := time.Now()
			if tc.legacyAge > 0 {
				// Simulate a pre-reprobe release while keeping the real mixed
				// support/quota state produced by MarkResult and persistence.
				for i := range records {
					records[i].UpdatedAt = now.Add(-tc.legacyAge)
					records[i].Quota.NextRecoverAt = now.Add(weekly)
					if records[i].Model != modelA {
						records[i].NextRetryAfter = now.Add(weekly)
					}
				}
			}
			restored := NewManager(nil, nil, nil)
			if _, err := restored.Register(WithSkipPersist(context.Background()), auth); err != nil {
				t.Fatal(err)
			}
			restored.SetCooldownStateStore(&mockCooldownStateStore{records: records})
			if err := restored.RestoreCooldownStates(context.Background()); err != nil {
				t.Fatal(err)
			}
			got, _ := restored.GetByID(auth.ID)
			state := got.ModelStates[modelA]
			if state == nil || !state.NextRetryAfter.Equal(wantSupportDeadline) {
				t.Fatalf("restored independent 404 deadline = %+v, want %v", state, wantSupportDeadline)
			}
			if state.Quota.NextRecoverAt.After(now.Add(quotaReprobeInterval)) {
				t.Fatalf("restored quota component exceeds re-probe bound: %+v", state.Quota)
			}
			afterQuota := now.Add(quotaReprobeInterval + time.Minute)
			if blocked, _, _ := isAuthBlockedForModel(got, modelA, afterQuota); !blocked {
				t.Fatal("model A lost its independent 12-hour support hold after quota expires")
			}
			if blocked, _, next := isAuthBlockedForModel(got, modelB, afterQuota); blocked {
				t.Fatalf("model B inherited independent support hold or unbounded quota until %v", next)
			}
			if blocked, _, _ := isAuthBlockedForModel(got, modelA, wantSupportDeadline.Add(time.Minute)); blocked {
				t.Fatal("model A remains blocked after its support hold expires")
			}
			if tc.legacyAge > quotaReprobeInterval {
				if blocked, _, _ := isAuthBlockedForModel(got, modelB, now); blocked {
					t.Fatal("expired legacy quota still blocks model B")
				}
			}
		})
	}
}

// An in-flight 429 that lands on an account still carrying a pre-bound
// multi-day quota deadline must not keep that deadline (max-with-existing).
func TestManager_MarkResult_DoesNotKeepOldMultiDayQuotaDeadline(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	for _, credentialScope := range []bool{false, true} {
		m, auth := newCooldownMonotonicManager(t, "gpt-reprobe-keep-a", "gpt-reprobe-keep-b")
		weekly := time.Now().Add(94 * time.Hour)
		m.mu.Lock()
		live := m.auths[auth.ID]
		if credentialScope {
			// Only a credential-scope 429 rewrites the auth-level hold.
			live.Quota = QuotaState{Exceeded: true, Reason: "credential_quota", NextRecoverAt: weekly}
		}
		for _, model := range []string{"gpt-reprobe-keep-a", "gpt-reprobe-keep-b"} {
			ensureModelState(live, model).Quota = QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: weekly}
		}
		m.mu.Unlock()
		short := time.Minute
		before := time.Now()
		m.MarkResult(context.Background(), Result{
			AuthID: auth.ID, Provider: auth.Provider, Model: "gpt-reprobe-keep-a",
			Success: false, RetryAfter: &short, CredentialScope: credentialScope,
			Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"},
		})
		updated, _ := m.GetByID(auth.ID)
		if blocked, _, next := isAuthBlockedForModel(updated, "gpt-reprobe-keep-a", before.Add(quotaReprobeInterval+time.Minute)); blocked {
			t.Fatalf("scope=%v: old weekly deadline kept, held for %v", credentialScope, next.Sub(before))
		}
	}
}
