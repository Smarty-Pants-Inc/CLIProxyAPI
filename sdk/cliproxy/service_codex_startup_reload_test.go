package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// The watcher's first full client load (and every auth-only rescan) calls the
// reload callback with the config pointer the service already runs. Force
// replacing the Codex executor there closes every live Codex websocket session
// (reason=executor_shutdown) for requests accepted after the listener started.
func TestWatcherReloadWithUnchangedConfigKeepsCodexExecutor(t *testing.T) {
	cfg := &config.Config{}
	service := &Service{cfg: cfg, coreManager: coreauth.NewManager(nil, nil, nil)}
	auth := &coreauth.Auth{ID: "codex-startup-reload", Provider: "codex", Status: coreauth.StatusActive}
	if _, errRegister := service.coreManager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	service.ensureExecutorsForAuth(auth)
	before, ok := service.coreManager.Executor("codex")
	if !ok || before == nil {
		t.Fatal("expected codex executor after startup bind")
	}

	service.applyWatcherConfigUpdate(cfg)

	after, _ := service.coreManager.Executor("codex")
	if after != before {
		t.Fatal("unchanged-config watcher reload replaced the codex executor and closed its live websocket sessions")
	}

	service.applyWatcherConfigUpdate(&config.Config{})
	if changed, _ := service.coreManager.Executor("codex"); changed == before {
		t.Fatal("changed config must still rebind the codex executor")
	}
}

// Config commits and their runtime application are separate steps. Two commits
// can land before either application runs (overlapping watcher reloads can
// deliver the same newest pointer twice). The first application is then
// superseded and skipped; the latest must still bind Codex to the latest config,
// and a later genuinely unchanged reload must keep that executor and its sessions.
func TestSupersededConfigCommitStillRebindsCodexToLatestConfig(t *testing.T) {
	codexBoundTo := func(t *testing.T, service *Service, cfg *config.Config) coreauth.ProviderExecutor {
		t.Helper()
		bound, ok := service.coreManager.Executor("codex")
		codexExec, isCodex := bound.(*executor.CodexAutoExecutor)
		if !ok || !isCodex || !codexExec.UsesConfig(cfg) {
			t.Fatalf("codex executor %T is not bound to the expected config", bound)
		}
		return bound
	}
	newService := func(t *testing.T) (*Service, *config.Config) {
		t.Helper()
		cfgA := &config.Config{}
		service := &Service{cfg: cfgA, coreManager: coreauth.NewManager(nil, nil, nil)}
		auth := &coreauth.Auth{ID: "codex-superseded-reload", Provider: "codex", Status: coreauth.StatusActive}
		if _, errRegister := service.coreManager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		service.ensureExecutorsForAuth(auth)
		codexBoundTo(t, service, cfgA)
		return service, cfgA
	}
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		distinct bool
	}{
		{name: "same latest pointer committed twice", distinct: false},
		{name: "B1 then B2", distinct: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, cfgA := newService(t)
			bound := codexBoundTo(t, service, cfgA)
			cfgB1 := &config.Config{}
			cfgB2 := cfgB1
			if tc.distinct {
				cfgB2 = &config.Config{}
			}

			commitB1 := service.commitConfigUpdate(cfgB1)
			commitB2 := service.commitConfigUpdate(cfgB2)

			// The superseded B1 application is skipped and binds nothing.
			if service.applyConfigRuntime(ctx, commitB1, false) {
				t.Fatal("superseded B1 application must be skipped")
			}
			if got, _ := service.coreManager.Executor("codex"); got != bound {
				t.Fatal("superseded B1 application replaced the codex executor")
			}

			// The latest application binds the latest config.
			if !service.applyConfigRuntime(ctx, commitB2, false) {
				t.Fatal("latest B2 application must run")
			}
			bound = codexBoundTo(t, service, cfgB2)

			// A late, superseded B1 application never replaces B2.
			if service.applyConfigRuntime(ctx, commitB1, false) {
				t.Fatal("late superseded B1 application must be skipped")
			}
			if got, _ := service.coreManager.Executor("codex"); got != bound {
				t.Fatal("late superseded B1 application replaced the B2 codex executor and closed its sessions")
			}

			// A genuinely unchanged reload keeps the B2 executor and its sessions.
			service.applyWatcherConfigUpdate(cfgB2)
			if got, _ := service.coreManager.Executor("codex"); got != bound {
				t.Fatal("unchanged reload after B2 replaced the codex executor and closed its sessions")
			}
		})
	}
}
