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
	"golang.org/x/crypto/bcrypt"
)

// A management password written through the v8 API must reach disk only as
// its bcrypt verifier, without relying on a config watcher.
func TestConfigV8ManagementSecretPersistedHashed(t *testing.T) {
	for _, tc := range []struct{ name, url, body string }{
		{"json path", "/v8/management/config/management/secret-key", `"plain-admin-pass"`},
		{"yaml document", "/v8/management/config.yaml", "management:\n  secret-key: plain-admin-pass\n"},
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
			r := gin.New()
			r.PUT("/v8/management/config.yaml", h.ConfigV8)
			r.PUT("/v8/management/config/*path", h.ConfigV8)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, tc.url, strings.NewReader(tc.body)))
			if w.Code != http.StatusOK {
				t.Fatalf("PUT status=%d body=%s", w.Code, w.Body.String())
			}
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(disk), "plain-admin-pass") {
				t.Fatalf("config file holds the plaintext management password:\n%s", disk)
			}
			loaded, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, hash := range []string{loaded.RemoteManagement.SecretKey, h.cfg.RemoteManagement.SecretKey} {
				if bcrypt.CompareHashAndPassword([]byte(hash), []byte("plain-admin-pass")) != nil {
					t.Fatalf("stored verifier %q does not accept the new password", hash)
				}
			}
		})
	}
}

// Clearing the management password with null/~/"" must leave no verifier:
// hashing the null spelling would enable remote management with the
// predictable password "null" (round-4 Astra finding 2).
func TestConfigV8ManagementSecretNullClears(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("old-admin-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, url, body string }{
		{"json scalar null", "/v8/management/config/management/secret-key", `null`},
		{"json scalar empty", "/v8/management/config/management/secret-key", `""`},
		{"json parent null", "/v8/management/config/management", `{"allow-remote":true,"secret-key":null}`},
		{"yaml null", "/v8/management/config.yaml", "management:\n  allow-remote: true\n  secret-key: null\n"},
		{"yaml tilde", "/v8/management/config.yaml", "management:\n  allow-remote: true\n  secret-key: ~\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("management:\n  allow-remote: true\n  secret-key: "+string(hash)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			h := &Handler{cfg: cfg, configFilePath: path, failedAttempts: map[string]*attemptInfo{}}
			r := gin.New()
			r.PUT("/v8/management/config.yaml", h.ConfigV8)
			r.PUT("/v8/management/config/*path", h.ConfigV8)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, tc.url, strings.NewReader(tc.body)))
			if w.Code != http.StatusOK {
				t.Fatalf("PUT status=%d body=%s", w.Code, w.Body.String())
			}
			loaded, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, got := range []string{loaded.RemoteManagement.SecretKey, h.cfg.RemoteManagement.SecretKey} {
				if got != "" {
					t.Fatalf("cleared secret left verifier %q", got)
				}
			}
			for _, guess := range []string{"null", "~", "old-admin-pass"} {
				if ok, _, _ := h.AuthenticateManagementKey("203.0.113.9", false, guess); ok {
					t.Fatalf("management accepted %q after the secret was cleared", guess)
				}
			}
		})
	}
}
