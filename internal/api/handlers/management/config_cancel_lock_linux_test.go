//go:build linux

package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"golang.org/x/sys/unix"
)

type observedConfigLockContext struct {
	context.Context
	queried chan struct{}
	once    sync.Once
}

func (c *observedConfigLockContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.queried) })
	return c.Context.Done()
}

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
	waiting := &observedConfigLockContext{Context: ctx, queried: make(chan struct{})}
	c.Request = httptest.NewRequest(http.MethodPut, "/debug", strings.NewReader(`{"value":true}`)).WithContext(waiting)
	done := make(chan struct{})
	go func() { defer close(done); h.PutDebug(c) }()
	// Done is consulted only by the cancellation-aware held-lock wait. This
	// proves cancellation occurs after acquisition was actually attempted.
	select {
	case <-waiting.queried:
	case <-time.After(2 * time.Second):
		t.Error("publication lock wait did not observe request ownership")
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
