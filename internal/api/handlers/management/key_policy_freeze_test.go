package management

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// F24A/F30 cut: while client-key policies are configured (runtime or on disk),
// management refuses every config.yaml write before it mutates shared state.
func TestKeyPolicyManagementConfigWritesRefused(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANAGEMENT_PASSWORD", "pw")
	digest := config.APIKeyDigest("K")
	for _, tc := range []struct {
		name, disk string
		runtime    bool
	}{
		{name: "runtime policy", disk: "debug: false\nws-auth: true\napi-key-policies:\n  - key-sha256: " + digest + "\n", runtime: true},
		{name: "deferred disk policy", disk: "debug: false\nws-auth: true\napi-keys: [K, L]\napi-key-policies:\n  - key-sha256: " + digest + "\n    daily-request-cap: 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.disk), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"K", "L"}}, WebsocketAuth: true}
			cfg.RemoteManagement.AllowRemote = true
			if tc.runtime {
				cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: digest}}
			}
			h := NewHandler(cfg, path, nil)
			engine := gin.New()
			mgmt := engine.Group("/v0/management")
			mgmt.Use(h.Middleware())
			mgmt.GET("/debug", h.GetDebug)
			mgmt.PUT("/debug", h.PutDebug)
			mgmt.DELETE("/api-keys", h.DeleteAPIKeys)
			for _, r := range []struct{ method, path, body string }{
				{"PUT", "/v0/management/debug", `{"value":true}`},
				{"DELETE", "/v0/management/api-keys?index=0", ""},
			} {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(r.method, r.path, strings.NewReader(r.body))
				req.Header.Set("Authorization", "Bearer pw")
				engine.ServeHTTP(rr, req)
				if rr.Code != http.StatusConflict {
					t.Fatalf("%s %s: status=%d body=%s, want 409", r.method, r.path, rr.Code, rr.Body.String())
				}
			}
			if disk, _ := os.ReadFile(path); string(disk) != tc.disk {
				t.Fatalf("disk policy rewritten:\n%s", disk)
			}
			if cfg.Debug || len(cfg.APIKeys) != 2 || cfg.APIKeys[0] != "K" {
				t.Fatalf("shared config mutated: debug=%t keys=%v", cfg.Debug, cfg.APIKeys)
			}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/v0/management/debug", nil)
			req.Header.Set("Authorization", "Bearer pw")
			engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("read refused: %d", rr.Code)
			}
		})
	}
}
