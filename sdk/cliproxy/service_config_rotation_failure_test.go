package cliproxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/crypto/bcrypt"
)

func TestWatcherManagementRotationApplicationResult(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	for _, failure := range []bool{true, false} {
		name := "ordinary-success"
		if failure {
			name = "pprof-shutdown-timeout"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			hash := func(key string) string {
				b, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			oldHash, newHash := hash("synthetic-old"), hash("synthetic-new")
			source := func(secret string, pprof bool) []byte {
				enabled := "false"
				if pprof {
					enabled = "true"
				}
				return []byte("auth-dir: '" + filepath.ToSlash(dir) + "'\nremote-management:\n  secret-key: '" + secret + "'\npprof:\n  enable: " + enabled + "\n")
			}
			if err := internalconfig.WriteConfigAtomic(path, source(oldHash, failure)); err != nil {
				t.Fatal(err)
			}
			old, err := internalconfig.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			server := api.NewServer(old, nil, sdkaccess.NewManager(), path)
			s := &Service{cfg: old, server: server, pprofServer: newPprofServer()}
			calls, successes := 0, 0
			apply := func(cfg *config.Config) bool {
				calls++
				// Retain executable RED coverage on the pre-repair void callback API.
				result := true
				if applier, ok := any(s).(interface{ applyWatcherConfigUpdate(*config.Config) bool }); ok {
					result = applier.applyWatcherConfigUpdate(cfg)
				} else {
					s.applyWatcherConfigUpdate(cfg)
				}
				if result {
					successes++
				}
				return result
			}
			w, err := defaultWatcherFactory(path, dir, func(cfg *config.Config) { apply(cfg) })
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if errStop := w.Stop(); errStop != nil {
					t.Error(errStop)
				}
			})
			// The additive result API keeps existing SDK watcher factories compatible.
			if observer, ok := any(w).(interface {
				SetReloadResultCallback(func(*config.Config) bool)
			}); ok {
				observer.SetReloadResultCallback(apply)
			}
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
			var recoverPprof func()
			if failure {
				started := make(chan struct{})
				mux := newPprofMux()
				profile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(started)
					mux.ServeHTTP(w, r)
				}))
				s.pprofServer.server = profile.Config
				s.pprofServer.enabled = true
				s.pprofServer.addr = profile.Listener.Addr().String()
				requestCtx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() {
					defer close(done)
					req, _ := http.NewRequestWithContext(requestCtx, http.MethodGet, profile.URL+"/debug/pprof/trace?seconds=30", nil)
					resp, errGet := profile.Client().Do(req)
					if errGet == nil {
						_, _ = io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
					}
				}()
				<-started
				recoverPprof = func() { cancel(); <-done; profile.Close() }
				defer func() {
					if recoverPprof != nil {
						recoverPprof()
					}
				}()
			}
			if err := internalconfig.WriteConfigAtomic(path, source(newHash, false)); err != nil {
				t.Fatal(err)
			}
			w.ReloadConfigIfChanged()
			// Revocation must precede even the failing pprof stop, not await recovery.
			checkKey("synthetic-old", http.StatusUnauthorized)
			checkKey("synthetic-new", http.StatusOK)
			if failure {
				if successes != 0 {
					t.Errorf("failed application acknowledged as successful: %d", successes)
				}
				recoverPprof()
				recoverPprof = nil
				w.ReloadConfigIfChanged()
				if calls != 2 || successes != 1 {
					t.Errorf("unchanged revision was not retried after recovery: calls=%d successes=%d", calls, successes)
				}
				checkKey("synthetic-old", http.StatusUnauthorized)
				checkKey("synthetic-new", http.StatusOK)
			} else if calls != 1 || successes != 1 {
				t.Errorf("ordinary rotation calls=%d successes=%d", calls, successes)
			}
			observedCalls := calls
			w.ReloadConfigIfChanged()
			if calls != observedCalls {
				t.Errorf("successful revision was not recorded: calls=%d want=%d", calls, observedCalls)
			}
		})
	}
}
