package management

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestManagementUploadValidationNoArtifacts(t *testing.T) {
	testManagementUploadValidationNoArtifacts(t, t.TempDir())
}

func testManagementUploadValidationNoArtifacts(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := config.WriteConfigAtomic(path, []byte("debug: false\n")); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(loadConfigFixture(t, path), path, nil)
	watch, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := watch.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	if err = watch.Add(dir); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PUT("/config.yaml", h.PutConfigYAML)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/config.yaml", strings.NewReader("debug: true\nremote-management:\n  secret-key: synthetic-upload-secret\n")))
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status=%d body=%s", rec.Code, rec.Body.String())
	}
	// Check both transient validation files and leaked lock inodes. Publication
	// staging and the live config's stable lock are expected, not validation files.
	// A later sentinel event drains all preceding upload events without relying
	// on a sleep or filesystem notification timing granularity.
	marker := filepath.Join(dir, "events-drained")
	if err = os.WriteFile(marker, nil, 0600); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
loop:
	for {
		select {
		case event := <-watch.Events:
			if strings.HasPrefix(filepath.Base(event.Name), "config-validate-") {
				t.Errorf("validation filesystem side effect: %s", event)
			}
			if event.Name == marker && event.Has(fsnotify.Create) {
				break loop
			}
		case errWatch := <-watch.Errors:
			t.Fatal(errWatch)
		case <-timer.C:
			t.Fatal("filesystem event sentinel was not delivered")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "config-validate-") {
			t.Errorf("leaked validation artifact: %s", entry.Name())
		}
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatalf("live stable lock missing: %v", err)
	}
	cfg := loadConfigFixture(t, path)
	if !cfg.Debug || strings.Contains(cfg.RemoteManagement.SecretKey, "synthetic-upload-secret") {
		t.Fatal("ordinary upload/hash persistence failed")
	}
}

func TestManagementUploadValidationLoaderChecks(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"syntax", "debug: [\n", http.StatusBadRequest},
		{"multiple-documents", "debug: false\n---\ndebug: true\n", http.StatusUnprocessableEntity},
		{"trusted-proxy", "trusted-proxies: [not-a-cidr]\n", http.StatusUnprocessableEntity},
		{"credential-weight", "codex-api-key:\n  - api-key: synthetic\n    weight: 1000001\n", http.StatusUnprocessableEntity},
		{"live-media-relay", "codex:\n  live-media-relay:\n    enabled: true\n    udp-port-min: 50000\n    udp-port-max: 40000\n", http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("debug: false\n")
			writeConfigFixtureBytes(t, path, baseline)
			h := NewHandler(loadConfigFixture(t, path), path, nil)
			router := gin.New()
			router.PUT("/config.yaml", h.PutConfigYAML)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/config.yaml", strings.NewReader(tc.body)))
			if rec.Code != tc.status {
				t.Errorf("status=%d want=%d body=%s", rec.Code, tc.status, rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, baseline)
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Errorf("invalid upload left artifacts: %v", entries)
			}
		})
	}
}
