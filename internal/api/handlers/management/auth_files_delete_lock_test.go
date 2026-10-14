package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestDeleteAuthFileWaitsForCredentialLock(t *testing.T) {
	for _, query := range []string{"name=locked.json", "name=locked.json&name=other.json", "all=true"} {
		t.Run(query, func(t *testing.T) {
			t.Setenv("MANAGEMENT_PASSWORD", "")
			dir := t.TempDir()
			path := filepath.Join(dir, "locked.json")
			if err := os.WriteFile(path, []byte(`{"type":"codex"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "other.json"), []byte(`{"type":"codex"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			manager := coreauth.NewManager(nil, nil, nil)
			if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: "locked.json", Provider: "codex", Attributes: map[string]string{"path": path}}); err != nil {
				t.Fatal(err)
			}
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
			h.tokenStore = &memoryAuthStore{}
			locked, release, lockDone := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				lockDone <- codexauth.WithFileLock(path, func() error { close(locked); <-release; return nil })
			}()
			<-locked
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			ctx.Request = httptest.NewRequest(http.MethodDelete, "/auth-files?"+query, nil)
			deleted := make(chan struct{})
			go func() { h.DeleteAuthFile(ctx); close(deleted) }()
			select {
			case <-deleted:
				close(release)
				<-lockDone
				t.Fatal("management deletion did not wait for the credential lock")
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("credential removed while refresh held lock: %v", err)
			}
			close(release)
			if err := <-lockDone; err != nil {
				t.Fatal(err)
			}
			<-deleted
			if recorder.Code != http.StatusOK {
				t.Fatalf("delete status = %d: %s", recorder.Code, recorder.Body.String())
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("credential not removed after refresh released lock: %v", err)
			}
			if _, ok := manager.GetByID("locked.json"); ok {
				t.Fatal("deleted credential is still registered")
			}
		})
	}
}
