package management

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// The writer passes the normal HTTP freeze middleware; a desired policy is
// installed on disk before it acquires ConfigV8's write lock. It must not erase it.
func TestNamedReviewConfigV8FreezeAtWriteBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const initial = "port: 8317\naccess:\n  api-keys: [K]\noauth:\n  providers:\n    aistudio:\n      ws-auth: true\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RemoteManagement.AllowRemote = true
	h := &Handler{cfg: cfg, configFilePath: path, envSecret: "pw", failedAttempts: map[string]*attemptInfo{}}
	passed := make(chan struct{})
	resume := make(chan struct{})
	done := make(chan struct{})
	r := gin.New()
	group := r.Group("/v8/management")
	group.Use(h.Middleware(), func(c *gin.Context) { close(passed); <-resume; c.Next() })
	group.PUT("/config", h.ConfigV8)
	group.PUT("/config/*path", h.ConfigV8)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v8/management/config", strings.NewReader(`{"server":{"port":8317},"access":{"api-keys":["K"]},"oauth":{"providers":{"aistudio":{"ws-auth":true}}}}`))
	req.Header.Set("Authorization", "Bearer pw")
	go func() { defer close(done); r.ServeHTTP(rr, req) }()
	select {
	case <-passed:
	case <-time.After(5 * time.Second):
		close(resume)
		<-done
		t.Fatalf("request did not reach post-middleware pause: status=%d body=%s", rr.Code, rr.Body.String())
	}
	desired := "port: 8317\napi-keys: [K]\nws-auth: true\napi-key-policies:\n  - key-sha256: " + config.APIKeyDigest("K") + "\n    allowed-auths: []\n    daily-request-cap: 0\n"
	if desiredCfg, err := config.ParseConfigBytes([]byte(desired)); err != nil || len(desiredCfg.APIKeyPolicies) != 1 {
		close(resume)
		<-done
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(desired), 0600); err != nil {
		close(resume)
		<-done
		t.Fatal(err)
	}
	if !h.policyConfigFrozen() {
		close(resume)
		<-done
		t.Fatal("desired policy did not arm the disk freeze")
	}
	close(resume)
	<-done
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := config.ParseConfigBytes(disk)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("status=%d body=%s remaining_desired_policies=%d", rr.Code, rr.Body.String(), len(loaded.APIKeyPolicies))
	if rr.Code != http.StatusConflict || string(disk) != desired {
		t.Fatalf("v8 write bypassed the post-middleware freeze and overwrote the deferred desired policy: status=%d remaining_policies=%d", rr.Code, len(loaded.APIKeyPolicies))
	}
}
