package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/crypto/bcrypt"
)

type rotationCooldownStore struct {
	fail  atomic.Bool
	saves atomic.Int32
}

func (*rotationCooldownStore) Load(context.Context) ([]coreauth.CooldownStateRecord, error) {
	return nil, nil
}

func (s *rotationCooldownStore) Save(context.Context, []coreauth.CooldownStateRecord) error {
	s.saves.Add(1)
	if s.fail.Load() {
		return errors.New("synthetic cooldown persistence failure")
	}
	return nil
}

func TestWatcherManagementRotationCooldownFailure(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	for _, failure := range []bool{true, false} {
		name := "ordinary-success"
		if failure {
			name = "store-failure-automatic-recovery"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			source := func(key string) []byte {
				hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				return []byte(fmt.Sprintf("auth-dir: %q\nplugins:\n  dir: %q\nsave-cooldown-status: true\nremote-management:\n  secret-key: %q\n", dir, filepath.Join(dir, "plugins"), hash))
			}
			publish := func(data []byte) {
				if err := internalconfig.WriteConfigAtomic(path, data); err != nil {
					t.Fatal(err)
				}
			}
			publish(source("synthetic-old"))
			old, err := internalconfig.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			store := &rotationCooldownStore{}
			manager := coreauth.NewManager(nil, nil, nil)
			manager.SetConfig(old)
			manager.SetCooldownStateStore(store)
			server := api.NewServer(old, manager, sdkaccess.NewManager(), path)
			s := &Service{cfg: old, server: server, coreManager: manager, cooldownStateStore: store}
			var calls atomic.Int32
			results := make(chan bool, 4)
			w, err := defaultWatcherFactory(path, dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			})
			w.SetReloadResultCallback(func(cfg *config.Config) bool {
				calls.Add(1)
				ok := s.applyWatcherConfigUpdate(cfg)
				results <- ok
				return ok
			})
			w.SetConfig(old)
			checkKey := func(key string, want int) {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/v0/management/config", nil)
				req.RemoteAddr = "127.0.0.1:1234"
				req.Header.Set("Authorization", "Bearer "+key)
				server.Handler().ServeHTTP(rec, req)
				if rec.Code != want {
					t.Errorf("management key %q status=%d, want %d", key, rec.Code, want)
				}
			}
			checkKey("synthetic-old", http.StatusOK)
			store.fail.Store(failure)
			publish(source("synthetic-new"))
			w.ReloadConfigIfChanged()
			if result := <-results; result == failure {
				t.Fatalf("first application result=%t, failure=%t", result, failure)
			}
			if store.saves.Load() != 1 {
				t.Fatalf("old cooldown store Save calls=%d, want 1", store.saves.Load())
			}
			// Check revocation before recovery, using the real management middleware.
			checkKey("synthetic-old", http.StatusUnauthorized)
			checkKey("synthetic-new", http.StatusOK)
			if failure {
				store.fail.Store(false)
				// No filesystem event or explicit reload: the captured revision must retry itself.
				select {
				case result := <-results:
					if !result {
						t.Fatal("automatic retry failed after cooldown store recovered")
					}
				case <-time.After(4 * time.Second):
					t.Fatal("failed revision did not retry automatically")
				}
				if store.saves.Load() != 2 {
					t.Errorf("recovered old cooldown store Save calls=%d, want 2", store.saves.Load())
				}
			}
			// This synchronizes with retry completion and proves its hash was recorded.
			wantCalls := int32(1)
			if failure {
				wantCalls = 2
			}
			w.ReloadConfigIfChanged()
			if calls.Load() != wantCalls {
				t.Errorf("successful revision not recorded: calls=%d, want %d", calls.Load(), wantCalls)
			}
			checkKey("synthetic-old", http.StatusUnauthorized)
			checkKey("synthetic-new", http.StatusOK)
		})
	}
}
