package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A later non-quota failure retains the earlier quota fields, but its retry
// deadline is independent: re-probing the quota must not shorten that hold.
func TestRestoreCooldownStates_LaterNonQuota(t *testing.T) {
	previous := quotaCooldownDisabled.Load()
	quotaCooldownDisabled.Store(false)
	t.Cleanup(func() { quotaCooldownDisabled.Store(previous) })

	for _, scope := range []struct {
		name, model string
	}{
		{name: "auth-level"},
		{name: "model-level", model: "later-nonquota-model"},
	} {
		t.Run(scope.name, func(t *testing.T) {
			for _, tc := range []struct {
				name        string
				age         time.Duration
				legacyQuota bool
				wantExpired bool
			}{
				{name: "live-quota"},
				{name: "legacy-quota-bounded", legacyQuota: true},
				{name: "expired-quota-cleared", age: quotaReprobeInterval + time.Minute, legacyQuota: true, wantExpired: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					ctx := context.Background()
					store := NewFileCooldownStateStore(t.TempDir())
					manager := NewManager(nil, nil, nil)
					manager.SetCooldownStateStore(store)
					auth := &Auth{ID: "later-nonquota-" + scope.name + "-" + tc.name, Provider: "xai", Status: StatusActive}
					if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
						t.Fatal(errRegister)
					}
					weekly := 94 * time.Hour
					manager.MarkResult(ctx, Result{
						AuthID: auth.ID, Provider: auth.Provider, Model: scope.model,
						RetryAfter: &weekly, Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "quota exhausted"},
					})
					manager.MarkResult(ctx, Result{
						AuthID: auth.ID, Provider: auth.Provider, Model: scope.model,
						Error: &Error{HTTPStatus: http.StatusNotFound, Message: "not found"},
					})

					// Read the real MarkResult snapshot from disk, not a constructed
					// stand-in: both failure paths keep the previous quota fields.
					records, errLoad := store.Load(ctx)
					if errLoad != nil {
						t.Fatal(errLoad)
					}
					index := -1
					for i := range records {
						if records[i].Model == scope.model {
							index = i
							break
						}
					}
					if index < 0 {
						t.Fatalf("no persisted record for model %q: %+v", scope.model, records)
					}
					record := &records[index]
					if record.LastError == nil || record.LastError.HTTPStatus != http.StatusNotFound || !record.Quota.Exceeded || record.Quota.Reason != "quota" {
						t.Fatalf("429 then 404 did not retain quota alongside the later error: %+v", record)
					}
					if got := record.NextRetryAfter.Sub(record.UpdatedAt); got != 12*time.Hour {
						t.Fatalf("MarkResult 404 hold = %v, want 12h", got)
					}
					if !record.Quota.NextRecoverAt.Before(record.NextRetryAfter) {
						t.Fatal("expected an independent non-quota hold beyond the quota deadline")
					}

					// Advance persisted timestamps instead of sleeping. Legacy quota
					// deadlines predate the hourly bound; the 404 hold stays live.
					record.UpdatedAt = record.UpdatedAt.Add(-tc.age)
					record.NextRetryAfter = record.NextRetryAfter.Add(-tc.age)
					if tc.legacyQuota {
						record.Quota.NextRecoverAt = record.UpdatedAt.Add(weekly)
					}
					wantRetry := record.NextRetryAfter
					wantQuota := boundQuotaHold(record.Quota.NextRecoverAt, record.UpdatedAt)
					if tc.wantExpired {
						wantQuota = time.Time{}
					}
					if errSave := store.Save(ctx, records); errSave != nil {
						t.Fatal(errSave)
					}

					restored := NewManager(nil, nil, nil)
					restored.SetCooldownStateStore(store)
					if _, errRegister := restored.Register(WithSkipPersist(ctx), &Auth{ID: auth.ID, Provider: auth.Provider, Status: StatusActive}); errRegister != nil {
						t.Fatal(errRegister)
					}
					if errRestore := restored.RestoreCooldownStates(ctx); errRestore != nil {
						t.Fatal(errRestore)
					}
					got, ok := restored.GetByID(auth.ID)
					if !ok {
						t.Fatal("restored auth missing")
					}
					unavailable, retry, quota, lastError := got.Unavailable, got.NextRetryAfter, got.Quota, got.LastError
					if scope.model != "" {
						state := existingModelState(got, scope.model)
						if state == nil {
							t.Fatal("restored independent model hold missing")
						}
						unavailable, retry, quota, lastError = state.Unavailable, state.NextRetryAfter, state.Quota, state.LastError
					}
					if !unavailable || !retry.Equal(wantRetry) {
						t.Errorf("restored independent 404 hold: unavailable=%v retry=%v, want unavailable=true retry=%v", unavailable, retry, wantRetry)
					}
					if lastError == nil || lastError.HTTPStatus != http.StatusNotFound {
						t.Errorf("restored LastError = %+v, want HTTP 404", lastError)
					}
					if quota.Exceeded == tc.wantExpired || !quota.NextRecoverAt.Equal(wantQuota) {
						t.Errorf("restored quota = %+v, want exceeded=%v next=%v", quota, !tc.wantExpired, wantQuota)
					}
					if tc.wantExpired && (quota.Reason != "" || quota.BackoffLevel != 0) {
						t.Errorf("expired quota fields not cleared: %+v", quota)
					}
					if blocked, _, _ := isAuthBlockedForModel(got, scope.model, wantRetry.Add(-time.Minute)); !blocked {
						t.Error("independent non-quota hold no longer blocks before its deadline")
					}

					// Restore re-persists the sanitized snapshot. It must preserve
					// the same independent hold and not resurrect an expired quota.
					persisted, errReload := store.Load(ctx)
					if errReload != nil {
						t.Fatal(errReload)
					}
					found := false
					for _, saved := range persisted {
						if saved.Model == scope.model {
							found = true
							if !saved.NextRetryAfter.Equal(wantRetry) || saved.Quota.Exceeded == tc.wantExpired || !saved.Quota.NextRecoverAt.Equal(wantQuota) {
								t.Errorf("re-persisted cooldown lost independent hold or quota sanitization: %+v", saved)
							}
						}
					}
					if !found {
						t.Error("restore discarded the still-live independent hold from persistence")
					}
				})
			}
		})
	}
}
