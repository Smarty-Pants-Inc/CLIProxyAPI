package management

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// The request-body seam gates a cooperating operator update after ConfigV8's
// initial read and before its publication, without sleeps or live providers.
type configV8ExternalEditBody struct {
	reader io.Reader
	edit   func()
}

func (b *configV8ExternalEditBody) Read(p []byte) (int, error) {
	if b.edit != nil {
		edit := b.edit
		b.edit = nil
		edit()
	}
	return b.reader.Read(p)
}

func TestForkConfigV8StaleTreeWrite(t *testing.T) {
	for _, tc := range []struct{ method, route, target, body string }{
		{http.MethodPatch, "/v8/management/config", "/v8/management/config", `{"observability":{"logs":{"debug":true}}}`},
		{http.MethodPut, "/v8/management/config/*path", "/v8/management/config/observability/logs/debug", `true`},
		{http.MethodPut, "/v8/management/config.yaml", "/v8/management/config.yaml", "server: {port: 8317}\nobservability: {logs: {debug: true}}\n"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("server: {port: 8317}\nobservability: {logs: {debug: false}}\n")
			newer := []byte("server: {port: 8999}\nobservability: {logs: {debug: false}}\n")
			if err := config.WriteConfigAtomic(path, baseline); err != nil {
				t.Fatal(err)
			}
			h := &Handler{cfg: loadConfigFixture(t, path), configFilePath: path}
			original := h.cfg
			router := gin.New()
			router.Handle(tc.method, tc.route, h.ConfigV8)
			body := &configV8ExternalEditBody{reader: strings.NewReader(tc.body), edit: func() {
				if err := config.WriteConfigAtomic(path, newer); err != nil {
					t.Fatal(err)
				}
			}}
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, body))
			if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"`+errStaleConfigMessage+`"}` {
				t.Fatalf("stale v8 tree write = %d %s", rec.Code, rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, newer)
			if h.cfg != original || h.cfg.Debug || h.reloadGeneration != 0 {
				t.Fatal("failed publication mutated or reloaded runtime config")
			}
		})
	}
}

func TestForkConfigV8PrivateAtomicPublicationAndRevision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := config.WriteConfigAtomic(path, []byte("server: {port: 8317}\n")); err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: loadConfigFixture(t, path), configFilePath: path}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.PATCH("/v8/management/config", h.ConfigV8)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/v8/management/config", strings.NewReader(`{"observability":{"logs":{"debug":true}}}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("v8 save = %d %s", rec.Code, rec.Body.String())
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("v8 save fell back to in-place truncation")
	}
	if runtime.GOOS != "windows" && after.Mode().Perm() != 0600 {
		t.Fatalf("v8 config publication permissions = %o", after.Mode().Perm())
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatalf("stable publication lock missing: %v", err)
	}
	// This full save checks that ConfigV8's runtime snapshot tracks the exact
	// canonical bytes published, not its intermediate pre-normalization tree.
	h.cfg.Debug = false
	if err = config.SaveConfigPreserveComments(path, h.cfg, true); err != nil {
		t.Fatalf("v8 runtime snapshot has stale publication revision: %v", err)
	}
}

func TestForkConfigV8PolicyFreeze(t *testing.T) {
	digest := config.APIKeyDigest("K")
	for _, tc := range []struct {
		name, raw string
		runtime   bool
	}{
		{"runtime", "server: {port: 8317}\naccess: {api-keys: [K]}\n", true},
		{"canonical disk", fmt.Sprintf("access: {api-keys: [K], api-key-policies: [{key-sha256: %s}]}\n", digest), false},
		{"legacy disk", fmt.Sprintf("api-keys: [K]\napi-key-policies: [{key-sha256: %s}]\n", digest), false},
		{"merged access disk", fmt.Sprintf("access: {<<: {api-keys: [K], api-key-policies: [{key-sha256: %s}]}}\n", digest), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfigFixtureBytes(t, path, []byte(tc.raw))
			cfg, err := config.ParseConfigBytes([]byte("access: {api-keys: [K]}\n"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.runtime {
				cfg.APIKeyPolicies = []config.APIKeyPolicy{{KeySHA256: digest}}
			}
			h := &Handler{cfg: cfg, configFilePath: path}
			router := gin.New()
			router.PATCH("/v8/management/config", h.ConfigV8)
			router.PUT("/v8/management/config.yaml", h.ConfigV8)
			for _, target := range []string{"/v8/management/config", "/v8/management/config.yaml"} {
				method, body := http.MethodPatch, `{"observability":{"logs":{"debug":true}}}`
				if strings.HasSuffix(target, ".yaml") {
					method, body = http.MethodPut, "server: {port: 8999}\n"
				}
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
				if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), errPolicyConfigFrozen) {
					t.Fatalf("frozen v8 save = %d %s", rec.Code, rec.Body.String())
				}
				assertConfigFixtureBytes(t, path, []byte(tc.raw))
				if h.cfg != cfg || cfg.Debug || h.reloadGeneration != 0 {
					t.Fatal("policy freeze mutated shared runtime state")
				}
			}
		})
	}
}

func TestForkConfigV8ClientKeyTreeEditsRefused(t *testing.T) {
	for _, tc := range []struct{ method, route, target, body string }{
		{http.MethodPut, "/v8/management/config/*path", "/v8/management/config/access/api-keys", `["X"]`},
		{http.MethodDelete, "/v8/management/config/*path", "/v8/management/config/access/api-keys", ""},
		{http.MethodPatch, "/v8/management/config", "/v8/management/config", `{"access":{"api-keys":["X"]}}`},
		{http.MethodPut, "/v8/management/config", "/v8/management/config", `{"server":{"port":8317}}`},
		{http.MethodPatch, "/v8/management/config", "/v8/management/config", `{"access":{"api-key-policies":[]}}`},
	} {
		t.Run(tc.method+tc.target+tc.body, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			baseline := []byte("access: {api-keys: [K, L]}\n")
			writeConfigFixtureBytes(t, path, baseline)
			h := &Handler{cfg: loadConfigFixture(t, path), configFilePath: path}
			keys := h.cfg.APIKeys
			router := gin.New()
			router.Handle(tc.method, tc.route, h.ConfigV8)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body)))
			if rec.Code != http.StatusConflict {
				t.Fatalf("client key edit = %d %s", rec.Code, rec.Body.String())
			}
			assertConfigFixtureBytes(t, path, baseline)
			if len(keys) != 2 || keys[0] != "K" || keys[1] != "L" || h.reloadGeneration != 0 {
				t.Fatal("client key edit mutated shared keys")
			}
		})
	}
}

func TestForkManagementV8PolicyOperationalExemptions(t *testing.T) {
	for path, expected := range map[string]string{
		"/v8/management/credentials":            "/auth-files",
		"/v8/management/credentials/status":     "/auth-files/status",
		"/v8/management/credentials/fields":     "/auth-files/fields",
		"/v8/management/credentials/refresh":    "/auth-files/refresh",
		"/v8/management/oauth/import":           "/vertex/import",
		"/v8/management/oauth/session":          "/oauth-session",
		"/v8/management/requests/api-call":      "/api-call",
		"/v8/management/routing/cooldown/reset": "/reset-quota",
		"/v8/management/observability/logs":     "/logs",
		"/v0/management/auth-files":             "/auth-files",
	} {
		if got := managementPolicyPath(path); got != expected || !policyFreezeExempt[got] {
			t.Errorf("operational exemption %s = %s, want %s", path, got, expected)
		}
	}
	if policyFreezeExempt[managementPolicyPath("/v8/management/config/*path")] {
		t.Fatal("v8 configuration routes bypass policy freeze")
	}
}

func TestForkManagementCallbackForwarderLoopback(t *testing.T) {
	forwarder, err := startCallbackForwarder(0, "codex", "http://127.0.0.1:8317/codex/callback")
	if err != nil {
		t.Fatal(err)
	}
	defer stopCallbackForwarderInstance(0, forwarder)
	host, _, err := net.SplitHostPort(forwarder.server.Addr)
	if err != nil || host != "127.0.0.1" {
		t.Fatalf("OAuth callback exposed outside loopback: %q, %v", forwarder.server.Addr, err)
	}
	// Cleanup by another session must not deregister the current owner.
	callbackForwardersMu.Lock()
	callbackForwarders[0] = &callbackForwarder{}
	callbackForwardersMu.Unlock()
	stopCallbackForwarderInstance(0, forwarder)
	callbackForwardersMu.Lock()
	current := callbackForwarders[0]
	delete(callbackForwarders, 0)
	callbackForwardersMu.Unlock()
	if current == nil || current == forwarder {
		t.Fatal("old session cleanup removed a new callback owner")
	}
}

func TestForkConfigV8YAMLRejectsTrailingDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	baseline := []byte("server: {port: 8317}\n")
	writeConfigFixtureBytes(t, path, baseline)
	h := &Handler{cfg: loadConfigFixture(t, path), configFilePath: path}
	router := gin.New()
	router.PUT("/v8/management/config.yaml", h.ConfigV8)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/v8/management/config.yaml", strings.NewReader("server: {port: 8999}\n---\nserver: {port: 9000}\n")))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("multiple-document v8 upload = %d %s", rec.Code, rec.Body.String())
	}
	assertConfigFixtureBytes(t, path, baseline)
}

func TestForkWriteConfigV8UsesPrivateAtomicPublisher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := WriteConfig(path, []byte("config-version: 8\nserver: {port: 8317}\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("config-version: 8")) {
		t.Fatalf("v8 raw publication failed: %v", err)
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatalf("raw v8 publication bypassed the stable lock: %v", err)
	}
}
