package management

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// These fixtures use real loaded snapshots and the real management save path.
// An unrelated external edit must not be overwritten by a stale full save.
func TestManagementStaleFullSave(t *testing.T) {
	for _, delayedHandler := range []bool{false, true} {
		name := "existing handler"
		if delayedHandler {
			name = "delayed snapshot"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("# synthetic fixture\ndebug: false\nrequest-retry: 1\napi-keys:\n  - synthetic-client-key\n")
			writeConfigFixtureBytes(t, path, baseline)
			cfg := loadConfigFixture(t, path)
			var h *Handler
			if !delayedHandler {
				h = NewHandler(cfg, path, nil)
			}
			newer := bytes.Replace(baseline, []byte("request-retry: 1"), []byte("request-retry: 7 # external unrelated update"), 1)
			writeConfigFixtureBytes(t, path, newer)
			if delayedHandler {
				h = NewHandler(cfg, path, nil)
			}

			router := gin.New()
			router.PUT("/v0/management/debug", h.PutDebug)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v0/management/debug", strings.NewReader(`{"value":true}`)))
			if rec.Code != http.StatusConflict {
				t.Errorf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "synthetic-client-key") || strings.Contains(rec.Body.String(), path) {
				t.Errorf("conflict response exposes fixture key or config path: %s", rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, newer)
		})
	}
}

func TestManagementFullSaveCurrentSnapshot(t *testing.T) {
	for _, externalBeforeLoad := range []bool{false, true} {
		name := "uncontended"
		if externalBeforeLoad {
			name = "external update before load"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("debug: false\nrequest-retry: 1\napi-keys:\n  - synthetic-client-key\n")
			writeConfigFixtureBytes(t, path, baseline)
			wantRetry := 1
			if externalBeforeLoad {
				writeConfigFixtureBytes(t, path, bytes.Replace(baseline, []byte("request-retry: 1"), []byte("request-retry: 7"), 1))
				wantRetry = 7
			}
			h := NewHandler(loadConfigFixture(t, path), path, nil)
			router := gin.New()
			router.PUT("/v0/management/debug", h.PutDebug)
			// A successful save must refresh the supplied snapshot for the next save.
			for _, value := range []string{"true", "false"} {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v0/management/debug", strings.NewReader(`{"value":`+value+`}`)))
				if rec.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
				}
				persisted := loadConfigFixture(t, path)
				if persisted.Debug != (value == "true") || persisted.RequestRetry != wantRetry {
					t.Fatalf("persisted debug=%v retry=%d, want debug=%s retry=%d", persisted.Debug, persisted.RequestRetry, value, wantRetry)
				}
			}
		})
	}
}

func TestManagementStaleFullSaveAfterAuthoritativeUpdate(t *testing.T) {
	for _, writer := range []string{"raw upload", "nested scalar"} {
		t.Run(writer, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("debug: false\nproxy-url: http://old.invalid\n")
			writeConfigFixtureBytes(t, path, baseline)
			h := NewHandler(loadConfigFixture(t, path), path, nil)
			if writer == "raw upload" {
				rawHandler := NewHandler(loadConfigFixture(t, path), path, nil)
				router := gin.New()
				router.PUT("/v0/management/config.yaml", rawHandler.PutConfigYAML)
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v0/management/config.yaml", strings.NewReader("debug: false\nproxy-url: http://new.invalid\n")))
				if rec.Code != http.StatusOK {
					t.Fatalf("raw upload status = %d, want 200; body=%s", rec.Code, rec.Body.String())
				}
			} else if err := config.SaveConfigPreserveCommentsUpdateNestedScalar(path, []string{"proxy-url"}, "http://new.invalid"); err != nil {
				t.Fatal(err)
			}
			newer, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.PUT("/v0/management/debug", h.PutDebug)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v0/management/debug", strings.NewReader(`{"value":true}`)))
			if rec.Code != http.StatusConflict {
				t.Fatalf("stale save status = %d, want 409; body=%s", rec.Code, rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, newer)
		})
	}
}

func TestManagementPluginStaleFullSave(t *testing.T) {
	for _, tc := range []struct {
		name, method, endpoint, body string
		handler                      func(*Handler, *gin.Context)
	}{
		{"config", http.MethodPut, "/v0/management/plugins/:id/config", `{"enabled":true}`, (*Handler).PutPluginConfig},
		{"enabled snapshot", http.MethodPatch, "/v0/management/plugins/:id/enabled", `{"enabled":true}`, (*Handler).PatchPluginEnabled},
		{"delete", http.MethodDelete, "/v0/management/plugins/:id", "", (*Handler).DeletePlugin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte(fmt.Sprintf("request-retry: 1\nplugins:\n  dir: %q\n  configs:\n    sample:\n      enabled: false\n", t.TempDir()))
			writeConfigFixtureBytes(t, path, baseline)
			h := NewHandler(loadConfigFixture(t, path), path, nil)
			newer := bytes.Replace(baseline, []byte("request-retry: 1"), []byte("request-retry: 7 # newer external bytes"), 1)
			writeConfigFixtureBytes(t, path, newer)
			router := gin.New()
			router.Handle(tc.method, tc.endpoint, func(c *gin.Context) { tc.handler(h, c) })
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, strings.Replace(tc.endpoint, ":id", "sample", 1), strings.NewReader(tc.body)))
			if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"`+errStaleConfigMessage+`"}` {
				t.Fatalf("stale plugin save response = %d %s, want secret-free 409", rec.Code, rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, newer)
			if h.reloadGeneration != 0 {
				t.Fatal("failed save generated a runtime reload snapshot")
			}
		})
	}
}

func TestRespondStaleConfigConflictClassifiesOnlySentinel(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		stale bool
	}{
		{"sentinel", config.ErrStaleConfig, true},
		{"wrapped sentinel", fmt.Errorf("synthetic-secret: %w", config.ErrStaleConfig), true},
		{"same text unrelated error", errors.New(config.ErrStaleConfig.Error()), false},
		{"io error", os.ErrPermission, false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			if got := respondStaleConfigConflict(ctx, tc.err); got != tc.stale {
				t.Fatalf("classified stale = %v, want %v", got, tc.stale)
			}
			if tc.stale {
				if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"`+errStaleConfigMessage+`"}` {
					t.Fatalf("conflict response = %d %s", rec.Code, rec.Body.String())
				}
			} else if rec.Body.Len() != 0 {
				t.Fatalf("non-stale error produced conflict response: %s", rec.Body.String())
			}
		})
	}
}

func writeConfigFixtureBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func loadConfigFixture(t *testing.T, path string) *config.Config {
	t.Helper()
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig fixture: %v", err)
	}
	return cfg
}

func assertConfigFixtureBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("config bytes changed: got %q, want exact newer bytes %q", got, want)
	}
}
