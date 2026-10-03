package management

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestKeyPolicyV8ConfigWritesFrozen(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, policies string
		runtime        bool
	}{
		{"runtime", "", true},
		{"deferred nested policy", "  api-key-policies:\n    - key-sha256: " + config.APIKeyDigest("K") + "\n", false},
		{"explicit nested empty policy", "  api-key-policies: []\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "config-version: 8\naccess:\n  api-keys: [K]\n" + tc.policies
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"K"}}, WebsocketAuth: true}
			if tc.runtime {
				cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: config.APIKeyDigest("K")}}
			}
			h := &Handler{cfg: cfg, configFilePath: path}
			router := gin.New()
			router.GET("/v8/management/config", h.ConfigV8)
			router.PATCH("/v8/management/config", h.ConfigV8)
			router.PUT("/v8/management/config.yaml", h.ConfigV8)
			for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
				router.Handle(method, "/v8/management/config/*path", h.ConfigV8)
			}
			for _, r := range []struct{ method, target, body string }{
				{http.MethodPatch, "/v8/management/config", `{"observability":{"logs":{"debug":true}}}`},
				{http.MethodPut, "/v8/management/config/observability/logs/debug", "true"},
				{http.MethodDelete, "/v8/management/config/access/api-key-policies", ""},
				{http.MethodPut, "/v8/management/config.yaml", "access: {api-keys: [X]}\n"},
			} {
				rr := httptest.NewRecorder()
				router.ServeHTTP(rr, httptest.NewRequest(r.method, r.target, strings.NewReader(r.body)))
				if rr.Code != http.StatusConflict {
					t.Fatalf("%s %s: %d %s", r.method, r.target, rr.Code, rr.Body.String())
				}
			}
			if disk, err := os.ReadFile(path); err != nil || string(disk) != raw || cfg.Debug || cfg.APIKeys[0] != "K" {
				t.Fatal("frozen v8 configuration mutated")
			}
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v8/management/config", nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("read refused: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestKeyPolicyV8JSONClientKeysRemainYAMLOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := "config-version: 8\naccess:\n  api-keys: [K, L]\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: path}
	router := gin.New()
	router.PATCH("/v8/management/config", h.ConfigV8)
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		router.Handle(method, "/v8/management/config/*path", h.ConfigV8)
	}
	for _, r := range []struct{ method, target, body string }{
		{http.MethodPut, "/v8/management/config/access/api-keys", `["X"]`},
		{http.MethodPatch, "/v8/management/config/access/api-keys", `["K","L"]`},
		{http.MethodDelete, "/v8/management/config/access/api-keys", ""},
		{http.MethodPatch, "/v8/management/config/access", `{"api-keys":["X"]}`},
		{http.MethodPatch, "/v8/management/config", `{"access":{"api-keys":["X"]}}`},
	} {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(r.method, r.target, strings.NewReader(r.body)))
		if rr.Code != http.StatusConflict {
			t.Fatalf("%s %s: %d %s", r.method, r.target, rr.Code, rr.Body.String())
		}
	}
	if disk, err := os.ReadFile(path); err != nil || string(disk) != raw || cfg.APIKeys[0] != "K" || cfg.APIKeys[1] != "L" {
		t.Fatal("JSON client-key write mutated configuration")
	}
}

func TestKeyPolicyV8OperationalAliasStillRequiresManagementAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("MANAGEMENT_PASSWORD", "test-password")
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: config.APIKeyDigest("K")}}}}
	cfg.RemoteManagement.AllowRemote = true
	h := NewHandler(cfg, "", nil)
	router := gin.New()
	group := router.Group("/v8/management", h.Middleware())
	group.POST("/credentials/refresh", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	for _, authenticated := range []bool{false, true} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v8/management/credentials/refresh", nil)
		want := http.StatusUnauthorized
		if authenticated {
			req.Header.Set("Authorization", "Bearer test-password")
			want = http.StatusNoContent
		}
		router.ServeHTTP(rr, req)
		if rr.Code != want {
			t.Fatalf("authenticated=%t: status=%d body=%s", authenticated, rr.Code, rr.Body.String())
		}
	}
}
