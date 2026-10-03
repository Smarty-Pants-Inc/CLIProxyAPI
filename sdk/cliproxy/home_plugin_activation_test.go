package cliproxy

import (
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/homeplugins"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	sdkpluginstore "github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginstore"
)

func homeActivationFailureConfig(t *testing.T) *config.Config {
	t.Helper()
	pluginsDir := t.TempDir()
	ext := ".so"
	switch homeplugins.CurrentPlatform().GOOS {
	case "darwin":
		ext = ".dylib"
	case "windows":
		ext = ".dll"
	}
	// An installed but unloadable library, like an incompatible auth plugin.
	if errWrite := os.WriteFile(filepath.Join(pluginsDir, "gate-v1.0.0"+ext), []byte("dummy"), 0o755); errWrite != nil {
		t.Fatalf("write plugin: %v", errWrite)
	}
	enabled := true
	cfg := &config.Config{}
	cfg.Home.Enabled = true
	cfg.Home.NodeID = "node-1"
	cfg.Plugins.Enabled = true
	cfg.Plugins.Dir = pluginsDir
	cfg.Plugins.Configs = map[string]config.PluginInstanceConfig{"gate": {Enabled: &enabled}}
	return cfg
}

// A Home plugin that failed to activate may be the exclusive frontend gate;
// the frontend must deny instead of running with an empty provider list.
func TestHomeFailedPluginActivationDeniesFrontend(t *testing.T) {
	cfg := homeActivationFailureConfig(t)
	service := &Service{cfg: cfg, pluginHost: pluginhost.New(), accessManager: sdkaccess.NewManager()}
	service.syncPluginRuntimeConfigForConfig(context.Background(), cfg)

	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	if _, authErr := service.accessManager.Authenticate(context.Background(), req); authErr == nil {
		t.Fatal("Authenticate() admitted a request while the Home plugin gate is not loaded")
	}

	// No enabled plugin: the normal provider list stays in place.
	cfg.Plugins.Configs = nil
	service.syncPluginRuntimeConfigForConfig(context.Background(), cfg)
	for _, provider := range service.accessManager.Providers() {
		if _, deny := provider.(homeActivationDenyProvider); deny {
			t.Fatal("deny gate kept after every enabled plugin is active")
		}
	}
}

// Failed activation must not publish Home nor mark the config synced.
func TestHomeFailedPluginActivationDoesNotPublish(t *testing.T) {
	cfg := homeActivationFailureConfig(t)
	client, writes := newHomePluginTaskTestClient(t, nil, 0)
	service := &Service{
		cfg:            &config.Config{Home: cfg.Home, Plugins: config.PluginsConfig{Enabled: true, Dir: cfg.Plugins.Dir}},
		pluginHost:     pluginhost.New(),
		homeGeneration: 1,
		homePluginSyncFetch: func(context.Context, sdkpluginstore.PluginSyncRequest) (sdkpluginstore.PluginSyncResponse, error) {
			return sdkpluginstore.PluginSyncResponse{
				SchemaVersion: sdkpluginstore.PluginSyncSchemaVersion,
				ExpiresAt:     time.Now().UTC().Add(time.Minute),
			}, nil
		},
	}
	work, errStage := service.stageHomeOverlayWithClient(context.Background(), cfg, client)
	if errStage != nil {
		t.Fatalf("stageHomeOverlayWithClient() error = %v", errStage)
	}
	published := false
	errFinalize := service.finalizeHomePluginWorkUntilDone(context.Background(), context.Background(), 1, client, work, func() bool {
		published = true
		return true
	})
	if !errors.Is(errFinalize, errHomePluginActivationFailed) {
		t.Fatalf("finalize error = %v, want errHomePluginActivationFailed", errFinalize)
	}
	if published {
		t.Fatal("Home was published after a failed plugin activation")
	}
	if service.homePluginSyncKey != "" {
		t.Fatal("failed activation marked the Home plugin config synced")
	}
	if writes.Load() != 1 {
		t.Fatalf("status writes = %d, want the failure reported once", writes.Load())
	}
}
