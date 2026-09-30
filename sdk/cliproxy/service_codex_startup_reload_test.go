package cliproxy

import (
	"context"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
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
