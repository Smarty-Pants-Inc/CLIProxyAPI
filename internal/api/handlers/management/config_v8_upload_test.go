package management

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Check at every body read, including before EOF, so a slow client cannot
// hold the management lock even when its upload is still within the limit.
type configV8UnlockedReader struct {
	t *testing.T
	h *Handler
	r io.Reader
}

func (r *configV8UnlockedReader) Read(p []byte) (int, error) {
	r.t.Helper()
	if !r.h.mu.TryLock() {
		r.t.Error("management lock held while reading request body")
	} else {
		r.h.mu.Unlock()
	}
	return r.r.Read(p)
}

func TestConfigV8OversizedUploadOutsideLock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, route := range []struct{ method, path string }{
		{http.MethodPut, "/v8/management/config.yaml"},
		{http.MethodPut, "/v8/management/config"},
		{http.MethodPatch, "/v8/management/config"},
	} {
		for _, chunked := range []bool{false, true} {
			name := route.method + route.path + "/plain"
			if chunked {
				name = route.method + route.path + "/chunked"
			}
			t.Run(name, func(t *testing.T) {
				// No config file: overflow must be rejected before any locked work.
				h := &Handler{}
				router := gin.New()
				router.Handle(route.method, route.path, h.ConfigV8)
				body := strings.Repeat("x", configV8MaxBodyBytes+1)
				req := httptest.NewRequest(route.method, route.path, &configV8UnlockedReader{t: t, h: h, r: strings.NewReader(body)})
				if chunked {
					req.ContentLength = -1
					req.TransferEncoding = []string{"chunked"}
				} else {
					req.ContentLength = int64(len(body))
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != http.StatusRequestEntityTooLarge {
					t.Fatalf("status=%d body=%s, want 413", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestConfigV8UploadWithinLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, method, route, body string
	}{
		{"JSON", http.MethodPatch, "/v8/management/config", `{"observability":{"logs":{"debug":true}}}`},
		{"YAML", http.MethodPut, "/v8/management/config.yaml", "config-version: 8\nserver: {port: 8317}\nobservability: {logs: {debug: true}}\n"},
		{"exact_limit", http.MethodPatch, "/v8/management/config", `{"observability":{"logs":{"debug":true}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("port: 8317\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			h := &Handler{cfg: cfg, configFilePath: path}
			router := gin.New()
			router.Handle(tc.method, tc.route, h.ConfigV8)
			body := tc.body
			if tc.name == "exact_limit" {
				body += strings.Repeat(" ", configV8MaxBodyBytes-len(body))
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.route, &configV8UnlockedReader{t: t, h: h, r: strings.NewReader(body)})
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			loaded, err := config.LoadConfig(path)
			if err != nil || !loaded.Debug {
				t.Fatalf("normal upload was not persisted: config=%+v error=%v", loaded, err)
			}
		})
	}
}
