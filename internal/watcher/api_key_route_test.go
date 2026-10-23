package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

// Exercise the real filesystem-event -> snapshot loader -> runtime callback
// boundary. Route changes must not rely on auth-file changes or policy reload rules.
func TestWatcherAPIKeyRoutesReload(t *testing.T) {
	for _, callbackKind := range []string{"notification", "acknowledging"} {
		t.Run(callbackKind, func(t *testing.T) {
			dir := t.TempDir()
			authDir := filepath.Join(dir, "auths")
			if err := os.Mkdir(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			source := func(routes []config.APIKeyRoute) []byte {
				t.Helper()
				base := fmt.Sprintf("oauth: {auth-dir: %q, providers: {aistudio: {ws-auth: false}}}\nplugins: {enabled: true, dir: %q}\naccess:\n  api-keys: [synthetic-watcher-client]\n", authDir, filepath.Join(dir, "plugins"))
				if routes == nil {
					return []byte(base)
				}
				routeYAML, err := yaml.Marshal(routes)
				if err != nil {
					t.Fatal(err)
				}
				return []byte(base + "  api-key-routes:\n    " + strings.ReplaceAll(string(routeYAML), "\n", "\n    ") + "\n")
			}
			if err := config.WriteConfigAtomic(path, source(nil)); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			changes := make(chan *config.Config, 16)
			w, err := NewWatcher(path, authDir, func(cfg *config.Config) { changes <- cfg.CloneForRuntime() })
			if err != nil {
				t.Fatal(err)
			}
			if callbackKind == "acknowledging" {
				w.SetReloadResultCallback(func(cfg *config.Config) bool {
					changes <- cfg.CloneForRuntime()
					return true
				})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			}()
			w.SetConfig(initial)
			if err = w.Start(ctx); err != nil {
				t.Fatal(err)
			}
			awaitRoutes := func(want []config.APIKeyRoute) {
				t.Helper()
				deadline := time.NewTimer(5 * time.Second)
				defer deadline.Stop()
				for {
					select {
					case got := <-changes:
						if !got.Plugins.Enabled || got.WebsocketAuth {
							t.Fatal("route reload test lost plugins-enabled/ws-auth-disabled starting state")
						}
						if reflect.DeepEqual(got.APIKeyRoutes, want) || (len(got.APIKeyRoutes) == 0 && len(want) == 0) {
							return
						}
					case <-deadline.C:
						t.Fatal("filesystem route change did not reach runtime reload callback")
					}
				}
			}
			awaitRoutes(nil)
			added := []config.APIKeyRoute{{KeySHA256: config.APIKeyDigest("synthetic-watcher-client"), Allow: []string{"GET /v1/models", "/v1/live"}}}
			changed := []config.APIKeyRoute{{KeySHA256: added[0].KeySHA256, Allow: []string{"POST /v1/live"}}}
			for _, routes := range [][]config.APIKeyRoute{added, changed, nil} {
				if err = config.WriteConfigAtomic(path, source(routes)); err != nil {
					t.Fatal(err)
				}
				awaitRoutes(routes)
			}
		})
	}
}
