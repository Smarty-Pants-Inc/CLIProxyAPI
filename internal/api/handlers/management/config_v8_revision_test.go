package management

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Exercise the actual YAML replacement route, not just a literal-path helper.
func TestConfigV8YAMLReadOnlyRevisionMerges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, field := range []string{
		"plugins/auth-revision",
		"credentials/concurrency/lifecycle-config-revision",
		"credentials/concurrency/observation-barrier-revision",
	} {
		for _, shape := range []string{"literal", "root merge", "nested merge", "parent merge", "alias", "merge sequence"} {
			for _, change := range []struct {
				name, old, next string
			}{
				{"introduce", "", "7"},
				{"introduce zero", "", "0"},
				{"introduce null", "", "null"},
				{"change", "7", "9"},
				{"clear", "7", "null"},
				{"remove", "7", ""},
				{"remove null", "null", ""},
			} {
				t.Run(field+"/"+shape+"/"+change.name, func(t *testing.T) {
					before := "config-version: 8\nserver: {port: 8317}\n" + configV8RevisionYAML(field, change.old, shape)
					body := "config-version: 8\nserver: {port: 8318}\n" + configV8RevisionYAML(field, change.next, shape)
					h, router, path, runtime := newConfigV8RevisionTestHandler(t, before)
					response := httptest.NewRecorder()
					router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/v8/management/config.yaml", strings.NewReader(body)))
					if response.Code != http.StatusBadRequest {
						t.Errorf("status=%d, want 400: %s", response.Code, response.Body.String())
					}
					var failure struct{ Error, Field string }
					if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || failure.Error != "read_only_field" || failure.Field != field {
						t.Errorf("want read_only_field for %s, got %s (decode error %v)", field, response.Body.String(), err)
					}
					assertConfigV8RevisionUnchanged(t, h, path, before, runtime)
				})
			}
		}
	}
}

func TestConfigV8YAMLUnchangedRevisionMerges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, field := range []string{
		"plugins/auth-revision",
		"credentials/concurrency/lifecycle-config-revision",
		"credentials/concurrency/observation-barrier-revision",
	} {
		for _, shape := range []string{"root merge", "nested merge", "parent merge", "alias", "merge sequence", "explicit override", "sequence precedence"} {
			t.Run(field+"/"+shape, func(t *testing.T) {
				before := "config-version: 8\nserver: {port: 8317}\n" + configV8RevisionYAML(field, "7", "literal")
				h, router, path, _ := newConfigV8RevisionTestHandler(t, before)
				body := "config-version: 8\nserver: {port: 8318}\n" + configV8RevisionYAML(field, "7", shape)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/v8/management/config.yaml", strings.NewReader(body)))
				if response.Code != http.StatusOK {
					t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
				}
				disk, err := config.LoadConfig(path)
				if err != nil {
					t.Fatal(err)
				}
				if disk.Port != 8318 || h.cfg.Port != 8318 {
					t.Fatal("unrelated server port update was not persisted and published")
				}
				if configV8TestRevision(disk, field) != 7 || configV8TestRevision(h.cfg, field) != 7 {
					t.Fatal("unchanged revision was not retained on disk and at runtime")
				}
			})
		}
	}
}

func TestConfigV8YAMLInvalidRevisionMerges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, body := range []string{
		"plugins: &cycle {<<: *cycle}\n",
		"<<: 7\n",
		"plugins: {<<: [7]}\n",
		"plugins: {auth-revision: 7, auth-revision: 9}\n",
	} {
		t.Run(body, func(t *testing.T) {
			before := "config-version: 8\nserver: {port: 8317}\n"
			h, router, path, runtime := newConfigV8RevisionTestHandler(t, before)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/v8/management/config.yaml", strings.NewReader(body)))
			if response.Code != http.StatusBadRequest {
				t.Errorf("status=%d, want 400: %s", response.Code, response.Body.String())
			}
			assertConfigV8RevisionUnchanged(t, h, path, before, runtime)
		})
	}
}

func configV8RevisionYAML(field, value, shape string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(field, "/")
	leaf := fmt.Sprintf("%s: %s", parts[len(parts)-1], value)
	wrap := func(content string, parents []string) string {
		for i := len(parents) - 1; i >= 0; i-- {
			content = parents[i] + ": {" + content + "}"
		}
		return content
	}
	parents := parts[:len(parts)-1]
	switch shape {
	case "root merge":
		return "<<: {" + wrap(leaf, parents) + "}\n"
	case "nested merge":
		return wrap("<<: {"+leaf+"}", parents) + "\n"
	case "parent merge":
		return parts[0] + ": {<<: {" + wrap(leaf, parents[1:]) + "}}\n"
	case "alias":
		// Plugin-owned settings are an allowed place to define an anchor.
		fixture := "configs: {revision-fixture: {value: &revision " + value + "}}"
		alias := parts[len(parts)-1] + ": *revision"
		if parts[0] == "plugins" {
			return "plugins: {" + fixture + ", <<: {" + alias + "}}\n"
		}
		return "plugins: {" + fixture + "}\n<<: {" + wrap(alias, parents) + "}\n"
	case "merge sequence":
		return wrap("<<: [{"+leaf+"}, {}]", parents) + "\n"
	case "explicit override":
		return wrap("<<: {"+parts[len(parts)-1]+": 99}, "+leaf, parents) + "\n"
	case "sequence precedence":
		return wrap("<<: [{"+leaf+"}, {"+parts[len(parts)-1]+": 99}]", parents) + "\n"
	default:
		return wrap(leaf, parents) + "\n"
	}
}

func newConfigV8RevisionTestHandler(t *testing.T, raw string) (*Handler, *gin.Engine, string, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Home = config.HomeConfig{Enabled: true, Host: "runtime.example"}
	runtime, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: path}
	router := gin.New()
	router.PUT("/v8/management/config.yaml", h.ConfigV8)
	return h, router, path, runtime
}

func assertConfigV8RevisionUnchanged(t *testing.T, h *Handler, path, before string, runtime []byte) {
	t.Helper()
	saved, err := os.ReadFile(path)
	if err != nil || string(saved) != before {
		t.Errorf("rejected write changed disk configuration: error=%v\n%s", err, saved)
	}
	next, err := json.Marshal(h.cfg)
	if err != nil || string(next) != string(runtime) || h.cfg.Home.Host != "runtime.example" || !h.cfg.Home.Enabled {
		t.Errorf("rejected write changed runtime configuration (marshal error %v)", err)
	}
	h.mu.Lock()
	generation := h.reloadGeneration
	h.mu.Unlock()
	if generation != 0 {
		t.Errorf("rejected write scheduled a runtime reload (generation %d)", generation)
	}
	staged, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".config-v8-*.yaml"))
	if err != nil || len(staged) != 0 {
		t.Errorf("rejected write left staging files: %v (error %v)", staged, err)
	}
}

func configV8TestRevision(cfg *config.Config, field string) int64 {
	switch field {
	case "plugins/auth-revision":
		return cfg.Plugins.AuthRevision
	case "credentials/concurrency/lifecycle-config-revision":
		return cfg.CredentialConcurrency.LifecycleConfigRevision
	default:
		return cfg.CredentialConcurrency.ObservationBarrierRevision
	}
}
