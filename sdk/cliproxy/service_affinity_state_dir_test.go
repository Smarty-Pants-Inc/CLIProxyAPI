package cliproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestServiceAffinityStateSavesDoNotTouchAuthDirectory(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(fmt.Sprintf("explicit=%t", explicit), func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("XDG_STATE_HOME", filepath.Join(root, "xdg"))
			authDir := filepath.Join(root, "auth")
			if err := os.Mkdir(authDir, 0o700); err != nil {
				t.Fatal(err)
			}
			// Old timestamp avoids false success on coarse-mtime filesystems.
			old := time.Unix(1000000000, 0)
			if err := os.Chtimes(authDir, old, old); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(authDir)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &internalconfig.Config{AuthDir: authDir, Routing: internalconfig.RoutingConfig{SessionAffinity: true}}
			if explicit {
				cfg.Routing.SessionAffinityStateDir = filepath.Join(root, "custom")
			}
			state := normalizedRoutingRuntimeState(cfg)
			if state.statePathUnavailable || state.statePath == "" {
				t.Fatalf("state unavailable: %+v", state)
			}
			selector := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
			defer selector.Stop()
			const saves = 12
			for i := 0; i < saves; i++ {
				payload := []byte(fmt.Sprintf(`{"output":[{"type":"compaction","encrypted_content":"block-%d"}]}`, i))
				if err := selector.RecordCompactionOutput("auth-a", cliproxyexecutor.Options{}, payload); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(state.statePath); err != nil {
					t.Fatalf("save %d not persisted: %v", i, err)
				}
				after, err := os.Stat(authDir)
				if err != nil || !after.ModTime().Equal(before.ModTime()) {
					t.Fatalf("save %d changed auth-dir mtime: %v, %v", i, after, err)
				}
			}
			entries, err := os.ReadDir(authDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("auth-dir contains runtime state: %v, %v", entries, err)
			}
			selector.Stop()
			restarted := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
			defer restarted.Stop()
			if got := restarted.Cache().Len(); got != saves {
				t.Fatalf("persisted bindings = %d, want %d", got, saves)
			}
		})
	}
}

func TestServiceAffinityUnsafeSDKDirectoryFailsClosed(t *testing.T) {
	authDir := t.TempDir()
	cfg := &internalconfig.Config{AuthDir: authDir, Routing: internalconfig.RoutingConfig{SessionAffinity: true, SessionAffinityStateDir: filepath.Join(authDir, "state")}}
	state := normalizedRoutingRuntimeState(cfg)
	if !state.statePathUnavailable || state.statePath != "" {
		t.Fatalf("unsafe SDK config not fail-closed: %+v", state)
	}
	service := &Service{cfg: &internalconfig.Config{}}
	if commit := service.commitConfigUpdate(cfg); commit.cfg != nil {
		t.Fatal("unsafe reload accepted")
	}
	if entries, err := os.ReadDir(authDir); err != nil || len(entries) != 0 {
		t.Fatalf("unsafe runtime created files: %v, %v", entries, err)
	}
}
