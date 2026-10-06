package management

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Pause authenticated requests after the middleware check, without timer sleeps.
func TestManagementDirectWritersFreezeAtWriteBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, method, route, target, body string
		handler                           func(*Handler) gin.HandlerFunc
	}{
		{"config PUT", http.MethodPut, "/config", "/config", `{"server":{"port":8318}}`, func(h *Handler) gin.HandlerFunc { return h.ConfigV8 }},
		{"config PATCH", http.MethodPatch, "/config", "/config", `{"server":{"port":8318}}`, func(h *Handler) gin.HandlerFunc { return h.ConfigV8 }},
		{"config DELETE", http.MethodDelete, "/config/*path", "/config/server/port", "", func(h *Handler) gin.HandlerFunc { return h.ConfigV8 }},
		{"config YAML", http.MethodPut, "/config.yaml", "/config.yaml", "server: {port: 8318}\n", func(h *Handler) gin.HandlerFunc { return h.ConfigV8 }},
		{"legacy config YAML", http.MethodPut, "/config.yaml", "/config.yaml", "port: 8318\n", func(h *Handler) gin.HandlerFunc { return h.PutConfigYAML }},
		{"plugin install", http.MethodPost, "/plugins/store/:id/install", "/plugins/store/sample-provider/install", "", func(h *Handler) gin.HandlerFunc { return h.InstallPluginFromStore }},
		{"plugin delete", http.MethodDelete, "/plugins/:id", "/plugins/sample-provider", "", func(h *Handler) gin.HandlerFunc { return h.DeletePlugin }},
	} {
		for _, policyLayout := range []string{"none", "legacy", "v8"} {
			t.Run(tc.name+"/"+policyLayout, func(t *testing.T) {
				const initial = "port: 8317\napi-keys: [K]\nplugins:\n  configs:\n    sample-provider:\n      enabled: false\n"
				path := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := config.LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				cfg.RemoteManagement.AllowRemote = true
				cfg.Plugins.Dir = t.TempDir()
				artifactURL := "https://downloads.example/sample-provider.zip"
				archive := makeManagementPluginStoreZip(t, "sample-provider"+managementPluginExtension(runtime.GOOS), "library-data")
				digest := sha256.Sum256(archive)
				h := &Handler{cfg: cfg, configFilePath: path, envSecret: "pw", failedAttempts: map[string]*attemptInfo{},
					pluginStoreRegistryURL: "https://registry.example/registry.json",
					pluginStoreHTTPClient: fakePluginStoreHTTPClient{
						"https://registry.example/registry.json": directRegistryJSON(artifactURL, hex.EncodeToString(digest[:])),
						artifactURL:                              archive,
					},
				}
				passed, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
				r := gin.New()
				base := "/v8/management"
				if tc.name == "legacy config YAML" {
					base = "/v0/management"
				}
				group := r.Group(base)
				group.Use(h.Middleware(), func(c *gin.Context) { close(passed); <-resume; c.Set(ConfigV8ContextKey, true); c.Next() })
				group.Handle(tc.method, tc.route, tc.handler(h))
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(tc.method, base+tc.target, strings.NewReader(tc.body))
				req.Header.Set("Authorization", "Bearer pw")
				go func() { defer close(done); r.ServeHTTP(rr, req) }()
				select {
				case <-passed:
				case <-time.After(5 * time.Second):
					close(resume)
					<-done
					t.Fatalf("post-middleware pause not reached: %d %s", rr.Code, rr.Body.String())
				}
				desired := initial
				if policyLayout == "legacy" {
					desired += "api-key-policies:\n  - key-sha256: " + config.APIKeyDigest("K") + "\n"
				} else if policyLayout == "v8" {
					desired += "access:\n  api-key-policies:\n    - key-sha256: " + config.APIKeyDigest("K") + "\n"
				}
				if err := os.WriteFile(path, []byte(desired), 0600); err != nil {
					close(resume)
					<-done
					t.Fatal(err)
				}
				close(resume)
				<-done
				disk, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("status=%d body=%s", rr.Code, rr.Body.String())
				if policyLayout == "none" {
					if rr.Code != http.StatusOK {
						t.Fatalf("ordinary write refused: %d %s", rr.Code, rr.Body.String())
					}
				} else {
					if rr.Code != http.StatusConflict || rr.Body.String() != `{"error":"`+errPolicyConfigFrozen+`"}` || string(disk) != desired {
						t.Fatalf("desired policy overwritten or wrong refusal: %d %s\ndisk=%s", rr.Code, rr.Body.String(), disk)
					}
					if h.cfg != cfg || cfg.Port != 8317 {
						t.Fatal("runtime configuration replaced on refusal")
					}
					if item, ok := cfg.Plugins.Configs["sample-provider"]; !ok || strings.Contains(marshalPluginRaw(t, item), "enabled: true") {
						t.Fatal("plugin runtime config mutated on refusal")
					}
				}
			})
		}
	}
}

// ConfigV8 holds h.mu while reading the body. Install the policy at that point
// to verify the recheck is at persistence, not only at handler entry.
type policyInstallingBody struct {
	io.Reader
	install func()
}

func (b *policyInstallingBody) Read(p []byte) (int, error) {
	if b.install != nil {
		b.install()
		b.install = nil
	}
	return b.Reader.Read(p)
}
func (b *policyInstallingBody) Close() error { return nil }

func TestConfigV8FreezeAfterHandlerRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("port: 8317\napi-keys: [K]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: path}
	desired := "port: 8317\napi-key-policies:\n  - key-sha256: " + config.APIKeyDigest("K") + "\n"
	r := gin.New()
	r.PUT("/v8/management/config", h.ConfigV8)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v8/management/config", nil)
	req.Body = &policyInstallingBody{Reader: strings.NewReader(`{"server":{"port":8318}}`), install: func() {
		if err := os.WriteFile(path, []byte(desired), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	r.ServeHTTP(rr, req)
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusConflict || string(disk) != desired || h.cfg != cfg {
		t.Fatalf("late freeze bypassed: %d %s\ndisk=%s", rr.Code, rr.Body.String(), disk)
	}
}
