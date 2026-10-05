package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPartialApplyFailureDoesNotSuppressOriginalConfig(t *testing.T) {
	for _, panicApply := range []bool{false, true} {
		t.Run(fmt.Sprint(panicApply), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			sourceA := []byte(fmt.Sprintf("auth-dir: %q\nrequest-retry: 2\n", dir))
			if err := os.WriteFile(path, sourceA, 0600); err != nil {
				t.Fatal(err)
			}
			w, err := NewWatcher(path, dir, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := w.Stop(); err != nil {
					t.Error(err)
				}
			}()
			w.storePersister = nil
			var manager coreauth.Manager
			calls := 0
			w.SetReloadResultCallback(func(cfg *config.Config) bool {
				calls++
				// This is the real manager side effect performed before service failures.
				manager.SetRetryConfig(cfg.RequestRetry, time.Duration(cfg.MaxRetryInterval)*time.Second, cfg.MaxRetryCredentials)
				if cfg.RequestRetry == 9 {
					if panicApply {
						panic("synthetic partial-apply failure")
					}
					return false
				}
				return true
			})
			retry := func() int64 {
				return reflect.ValueOf(&manager).Elem().FieldByName("requestRetry").FieldByName("v").Int()
			}
			w.reloadConfigIfChanged()
			if retry() != 2 {
				t.Fatal("A not applied to manager")
			}
			if err := os.WriteFile(path, []byte(fmt.Sprintf("auth-dir: %q\nrequest-retry: 9\n", dir)), 0600); err != nil {
				t.Fatal(err)
			}
			w.reloadConfigIfChanged()
			if retry() != 9 {
				t.Fatal("fixture did not partially apply B")
			}
			if err := os.WriteFile(path, sourceA, 0600); err != nil {
				t.Fatal(err)
			}
			w.reloadConfigIfChanged()
			if calls != 3 || retry() != 2 {
				t.Fatalf("A rollback suppressed: calls=%d manager retry=%d", calls, retry())
			}
		})
	}
}
