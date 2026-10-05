package management

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// Used by the exact-base fault-injection overlay. Fixed production deliberately
// has no post-publication loader to inject: parsing precedes the commit boundary.
func failPublishedReload(string) (*config.Config, error) {
	return nil, errors.New("synthetic post-publication load failure")
}

func snapshotCommitRequest(fn func(*gin.Context), body, version string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	if version != "" {
		c.Request.Header.Set("If-Match", version)
	}
	fn(c)
	return rec
}

func TestYAMLCommitKeepsMatchingSnapshotAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\nrequest-retry: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: initial, configFilePath: path, configVersion: initial.ConfigFileVersion}
	source := "# preserved\nrequest-retry: 9   # retain spacing\nremote-management:\n  secret-key: 'synthetic-test-key'\n"
	rec := snapshotCommitRequest(h.PutConfigYAML, source, initial.ConfigFileVersion)
	// The injected base loader fails here after B is published. Regardless of
	// status, A must never be granted the version authority of B.
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected YAML status: %d %s", rec.Code, rec.Body.String())
	}
	if h.configVersion != h.cfg.ConfigFileVersion {
		t.Error("old snapshot acquired the new file CAS authority")
	}
	reloaded := make(chan struct{})
	h.SetConfigReloadHook(func(context.Context, *config.Config) { close(reloaded) })
	mutation := snapshotCommitRequest(h.PutDebug, `{"value":true}`, "")
	if mutation.Code == http.StatusOK {
		<-reloaded
		h.reloadMu.Lock()
		h.reloadMu.Unlock()
	}
	disk, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.RequestRetry != 9 {
		t.Errorf("ordinary mutation replaced B with stale A: retry=%d", disk.RequestRetry)
	}
}

func TestYAMLHashesManagementKeyBeforeSingleSourcePreservingCommit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: initial, configFilePath: path, configVersion: initial.ConfigFileVersion}
	source := "request-retry: 9   # exact spacing\nremote-management:\n  secret-key: 'synthetic-test-key' # retained\n"
	rec := snapshotCommitRequest(h.PutConfigYAML, source, initial.ConfigFileVersion)
	if rec.Code != http.StatusOK {
		t.Fatalf("YAML status: %d %s", rec.Code, rec.Body.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "request-retry: 9   # exact spacing") {
		t.Error("post-publication key rewrite changed non-secret source bytes")
	}
	if strings.Contains(string(data), "synthetic-test-key") {
		t.Error("plaintext key published")
	}
	version, err := config.ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if h.cfg.RequestRetry != 9 || h.cfg.ConfigFileVersion != version || h.configVersion != version {
		t.Fatal("snapshot and publication version differ")
	}
}
