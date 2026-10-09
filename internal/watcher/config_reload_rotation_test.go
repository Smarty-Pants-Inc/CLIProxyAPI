package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestWatcherManagementRotationInterleavings(t *testing.T) {
	for _, scenario := range []string{"rotation-during-read", "failed-load-then-success", "two-quick-rotations", "write-between-read-and-record"} {
		t.Run(scenario, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "watcher-key-rotation-")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			authDir := filepath.Join(dir, "auths")
			if err = os.Mkdir(authDir, 0700); err != nil {
				t.Fatal(err)
			}
			hash := func(key string) string {
				data, errHash := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
				if errHash != nil {
					t.Fatal(errHash)
				}
				return string(data)
			}
			source := func(key string, retry int) []byte {
				return []byte(fmt.Sprintf("auth-dir: %q\nplugins:\n  dir: %q\nremote-management:\n  secret-key: %q\nrequest-retry: %d\n", authDir, filepath.Join(dir, "plugins"), hash(key), retry))
			}
			old := source("synthetic-old", 1)
			rotated := source("synthetic-new", 2)
			latest := source("synthetic-latest", 3)
			publish := func(data []byte) {
				if err := config.WriteConfigAtomic(path, data); err != nil {
					t.Fatal(err)
				}
			}
			publish(old)
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			var installed *config.Config
			w, err := NewWatcher(path, authDir, func(cfg *config.Config) { installed = cfg })
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			}()
			w.SetConfig(cfg)
			w.ReloadConfigIfChanged()
			installed = nil
			publish(rotated)
			switch scenario {
			case "rotation-during-read":
				reads := 0
				w.reloadConfigIfChangedWithRead(func(path string) ([]byte, error) {
					data, errRead := os.ReadFile(path)
					reads++
					if reads == 1 {
						publish(old)
					}
					return data, errRead
				})
				if installed == nil || bcrypt.CompareHashAndPassword([]byte(installed.RemoteManagement.SecretKey), []byte("synthetic-new")) != nil {
					t.Fatal("applied a different snapshot than the first read")
				}
				if w.lastConfigHash != "" {
					t.Fatal("concurrent revert was marked observed")
				}
				w.ReloadConfigIfChanged()
				if bcrypt.CompareHashAndPassword([]byte(installed.RemoteManagement.SecretKey), []byte("synthetic-old")) != nil {
					t.Fatal("concurrent revert was skipped")
				}
				publish(rotated)
			case "failed-load-then-success":
				publish([]byte("remote-management: [invalid"))
				w.ReloadConfigIfChanged()
				if installed != nil || w.lastConfigHash != "" {
					t.Fatal("failed load recorded or applied a revision")
				}
				publish(rotated)
			case "two-quick-rotations":
				publish(latest)
			case "write-between-read-and-record":
				reads := 0
				w.reloadConfigIfChangedWithRead(func(path string) ([]byte, error) {
					data, errRead := os.ReadFile(path)
					reads++
					if reads == 2 {
						publish(latest)
					}
					return data, errRead
				})
				if w.lastConfigHash != "" {
					t.Fatal("publication between final read and record was marked observed")
				}
			}
			w.ReloadConfigIfChanged()
			want := "synthetic-new"
			if scenario == "two-quick-rotations" || scenario == "write-between-read-and-record" {
				want = "synthetic-latest"
			}
			if installed == nil || bcrypt.CompareHashAndPassword([]byte(installed.RemoteManagement.SecretKey), []byte(want)) != nil {
				t.Fatal("completed rotation was not installed")
			}
			if bcrypt.CompareHashAndPassword([]byte(installed.RemoteManagement.SecretKey), []byte("synthetic-old")) == nil {
				t.Fatal("old management key remains accepted")
			}
		})
	}
}
