//go:build linux

package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"golang.org/x/sys/unix"
)

func TestCanceledConfigMutationDoesNotPublishAfterFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("debug: false\nrequest-retry: 2\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	unlocked := false
	release := func() {
		if !unlocked {
			if err := unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
				t.Error(err)
			}
			unlocked = true
		}
	}
	defer release()
	h := &Handler{cfg: cfg, configFilePath: path, configVersion: cfg.ConfigFileVersion, envSecret: "synthetic-test-key"}
	reloaded := make(chan struct{})
	h.SetConfigReloadHook(func(context.Context, *config.Config) { close(reloaded) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/debug", strings.NewReader(`{"value":true}`)).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.PutDebug(c) }()
	// Observe the mutation owning h.mu while the external publication lock is held.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	queued := false
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for !queued {
		if h.mu.TryLock() {
			h.mu.Unlock()
		} else {
			queued = true
			break
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			release()
			<-done
			t.Fatal("mutation did not queue at file lock")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("canceled queued mutation retained the management mutex")
		release()
		<-done
	}
	if rec.Code == http.StatusOK {
		<-reloaded
		h.reloadMu.Lock()
		h.reloadMu.Unlock()
	}
	// Joining done proves the mutex/rollback defer has completed before auth/reload.
	allowed, _, _ := h.AuthenticateManagementKey("127.0.0.1", true, "synthetic-test-key")
	if !allowed {
		t.Error("authorization unavailable after cancellation")
	}
	h.SetConfig(cfg)
	release()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Errorf("canceled queued edit published: %q", data)
	}
	if cfg.Debug {
		t.Error("canceled edit escaped its private snapshot")
	}
}
