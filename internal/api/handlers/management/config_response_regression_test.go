package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type stalledConfigWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
}

func (w *stalledConfigWriter) Header() http.Header { return w.header }
func (w *stalledConfigWriter) WriteHeader(int)     {}
func (w *stalledConfigWriter) Write(b []byte) (int, error) {
	close(w.entered)
	<-w.release
	return len(b), nil
}

func TestConfigResponseDoesNotBlockAuthorizationOrReload(t *testing.T) {
	for _, name := range []string{"config", "excluded", "alias", "keys"} {
		t.Run(name, func(t *testing.T) {
			cfg := &config.Config{OAuthExcludedModels: map[string][]string{"codex": {strings.Repeat("m", 8<<20)}}}
			cfg.APIKeys = []string{strings.Repeat("k", 8<<20)}
			h := &Handler{cfg: cfg, envSecret: "synthetic-test-key"}
			writer := &stalledConfigWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
			c, _ := gin.CreateTestContext(writer)
			c.Request = httptest.NewRequest(http.MethodGet, "/config", nil)
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch name {
				case "config":
					h.GetConfig(c)
				case "excluded":
					h.GetOAuthExcludedModels(c)
				case "alias":
					h.GetOAuthModelAlias(c)
				case "keys":
					h.GetAPIKeys(c)
				}
			}()
			<-writer.entered
			authDone := make(chan bool, 1)
			go func() {
				ok, _, _ := h.AuthenticateManagementKey("127.0.0.1", true, "synthetic-test-key")
				authDone <- ok
			}()
			reloadDone := make(chan struct{})
			go func() { h.SetConfig(cfg.CloneForRuntime()); close(reloadDone) }()
			// Always release and join every goroutine, including on the RED path.
			authConsumed := false
			defer func() {
				close(writer.release)
				<-done
				<-reloadDone
				if !authConsumed {
					<-authDone
				}
			}()
			select {
			case ok := <-authDone:
				authConsumed = true
				if !ok {
					t.Error("synthetic authorization failed")
				}
			case <-time.After(2 * time.Second):
				t.Error("stalled response holds authorization mutex")
				return
			}
			select {
			case <-reloadDone:
			case <-time.After(2 * time.Second):
				t.Error("stalled response blocks SetConfig")
			}
		})
	}
}
