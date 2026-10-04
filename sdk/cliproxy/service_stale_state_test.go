package cliproxy

import (
	"context"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestServiceApplyCoreAuthAddOrUpdate_DeleteReAddDoesNotInheritStaleRuntimeState(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}

	authID := "service-stale-state-auth"
	modelID := "stale-model"
	lastRefreshedAt := time.Date(2026, time.March, 1, 8, 0, 0, 0, time.UTC)
	nextRefreshAfter := lastRefreshedAt.Add(30 * time.Minute)

	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(authID)
	})

	service.applyCoreAuthAddOrUpdate(context.Background(), &coreauth.Auth{
		ID:               authID,
		Provider:         "claude",
		Status:           coreauth.StatusActive,
		LastRefreshedAt:  lastRefreshedAt,
		NextRefreshAfter: nextRefreshAfter,
		ModelStates: map[string]*coreauth.ModelState{
			modelID: {
				Quota: coreauth.QuotaState{BackoffLevel: 7},
			},
		},
	})

	service.applyCoreAuthRemoval(context.Background(), authID)

	if _, ok := service.coreManager.GetByID(authID); ok {
		t.Fatalf("expected auth %q to be removed from runtime state", authID)
	}

	service.applyCoreAuthAddOrUpdate(context.Background(), &coreauth.Auth{
		ID:       authID,
		Provider: "claude",
		Status:   coreauth.StatusActive,
	})

	updated, ok := service.coreManager.GetByID(authID)
	if !ok || updated == nil {
		t.Fatalf("expected re-added auth to be present")
	}
	if updated.Disabled {
		t.Fatalf("expected re-added auth to be active")
	}
	if !updated.LastRefreshedAt.IsZero() {
		t.Fatalf("expected LastRefreshedAt to reset on delete -> re-add, got %v", updated.LastRefreshedAt)
	}
	if !updated.NextRefreshAfter.IsZero() {
		t.Fatalf("expected NextRefreshAfter to reset on delete -> re-add, got %v", updated.NextRefreshAfter)
	}
	if len(updated.ModelStates) != 0 {
		t.Fatalf("expected ModelStates to reset on delete -> re-add, got %d entries", len(updated.ModelStates))
	}
	if models := registry.GetGlobalRegistry().GetModelsForClient(authID); len(models) == 0 {
		t.Fatalf("expected re-added auth to re-register models in global registry")
	}
}

func TestForceHomeRuntimeConfigEnablesUsageStatistics(t *testing.T) {
	cfg := &config.Config{
		UsageStatisticsEnabled: false,
		DisableCooling:         false,
		SaveCooldownStatus:     true,
	}

	forceHomeRuntimeConfig(cfg)

	if !cfg.UsageStatisticsEnabled {
		t.Fatal("expected home runtime config to force usage statistics enabled")
	}
	if !cfg.DisableCooling {
		t.Fatal("expected home runtime config to force cooling disabled")
	}
	if cfg.SaveCooldownStatus {
		t.Fatal("expected home runtime config to force cooldown status persistence disabled")
	}
}

func TestLifetimeRegistryObservesBarrierFromAppliedHomeConfig(t *testing.T) {
	registry := executionregistry.New()
	manager := coreauth.NewManager(nil, nil, nil)
	cfg := internalconfig.DefaultCredentialInFlightConfig()
	cfg.SnapshotInterval = "30ms"

	if errApply := applyHomeInFlightPublisherConfig(manager, cfg); errApply != nil {
		t.Fatal(errApply)
	}
	applyHomeObservationBarrier(registry, 14)

	if freeze := registry.FreezeInFlight(time.Now().UTC()); freeze.BarrierRevision != 14 {
		t.Fatalf("barrier revision = %d, want 14", freeze.BarrierRevision)
	}
	if got := manager.HomeInFlightPublisherConfig(); got.SnapshotInterval != 30*time.Millisecond {
		t.Fatalf("publisher interval = %v, want 30ms", got.SnapshotInterval)
	}
}

func TestApplyHomeOverlayDoesNotApplyWithoutReadyClient(t *testing.T) {
	baseCfg := &config.Config{UsageStatisticsEnabled: false, SaveCooldownStatus: true}
	baseCfg.Home.Enabled = true
	service := &Service{cfg: baseCfg}

	service.applyHomeOverlay(&config.Config{
		UsageStatisticsEnabled: false,
		SaveCooldownStatus:     true,
	})

	if service.cfg == nil || service.cfg.UsageStatisticsEnabled {
		t.Fatal("unready home overlay changed usage statistics")
	}
	if !service.cfg.Home.Enabled {
		t.Fatal("unready home overlay changed local home settings")
	}
	if !service.cfg.SaveCooldownStatus {
		t.Fatal("unready home overlay changed cooldown status persistence")
	}
}

// The watcher reload path copies the existing model holds into the reloaded
// record; the failure scope recorded with them must travel too, so a Codex
// quota hold stays releasable by the usage re-probe after its auth file is
// rewritten, while a credential-wide failure's scope is not forgotten.
func TestServiceApplyCoreAuthAddOrUpdate_ReloadCarriesFailureScope(t *testing.T) {
	for _, tc := range []struct {
		name        string
		authWide403 bool
		want        string
	}{
		{"explicit-model-quota", false, coreauth.FailureScopeModel},
		{"auth-wide-403", true, coreauth.FailureScopeCredential},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &Service{cfg: &config.Config{}, coreManager: coreauth.NewManager(nil, nil, nil)}
			authID := "service-scope-reload-" + tc.name
			t.Cleanup(func() { GlobalModelRegistry().UnregisterClient(authID) })
			fileRecord := func() *coreauth.Auth {
				return &coreauth.Auth{ID: authID, Provider: "codex", Status: coreauth.StatusActive, Metadata: map[string]any{"account_id": "acct"}}
			}
			ctx := coreauth.WithSkipPersist(context.Background())
			service.applyCoreAuthAddOrUpdate(ctx, fileRecord())
			reset := 72 * time.Hour
			service.coreManager.MarkResult(ctx, coreauth.Result{AuthID: authID, Provider: "codex", Model: "gpt-5.5", RetryAfter: &reset,
				Error: &coreauth.Error{HTTPStatus: 429, Message: "usage_limit_reached"}})
			if tc.authWide403 {
				service.coreManager.MarkResult(ctx, coreauth.Result{AuthID: authID, Provider: "codex", Error: &coreauth.Error{HTTPStatus: 403, Message: "account deactivated"}})
			}
			service.applyCoreAuthAddOrUpdate(ctx, fileRecord())
			reloaded, ok := service.coreManager.GetByID(authID)
			if !ok || reloaded.ModelStates["gpt-5.5"] == nil || !reloaded.ModelStates["gpt-5.5"].Quota.Exceeded {
				t.Fatalf("setup: reload did not carry the model hold: %+v", reloaded)
			}
			if reloaded.FailureScope != tc.want {
				t.Fatalf("FailureScope after reload = %q, want %q", reloaded.FailureScope, tc.want)
			}
		})
	}
}
