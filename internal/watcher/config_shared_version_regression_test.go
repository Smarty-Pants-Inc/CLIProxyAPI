package watcher

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestManagementPublicationDuringRuntimeApplyIsNotObservedEarly(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("auth-dir: %q\nrequest-retry: 1\n", authDir)), 0600); err != nil {
		t.Fatal(err)
	}
	var retries []int
	w, err := NewWatcher(path, authDir, func(cfg *config.Config) {
		retries = append(retries, cfg.RequestRetry)
		if cfg.RequestRetry == 1 {
			// Server installs the exact callback pointer in management. Publishing B
			// must not modify A while its runtime callback is still applying it.
			h := management.NewHandler(cfg, path, nil)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest("PUT", "/v0/management/request-retry", bytes.NewBufferString(`{"value":2}`))
			h.PutRequestRetry(c)
			if rec.Code != 200 {
				t.Fatalf("management save=%d %s", rec.Code, rec.Body.String())
			}
			if cfg.RequestRetry != 1 {
				t.Fatal("management publication modified an applying runtime snapshot")
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	}()
	w.reloadConfigIfChanged()
	w.reloadConfigIfChanged()
	if len(retries) != 2 || retries[0] != 1 || retries[1] != 2 {
		t.Fatalf("published retry settings marked observed without applying: %v", retries)
	}
}
