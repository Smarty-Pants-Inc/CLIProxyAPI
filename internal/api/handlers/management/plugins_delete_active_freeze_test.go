//go:build cgo && (linux || darwin || freebsd)

package management

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
)

func TestDeleteActivePluginFreezePreservesServiceAfterAdmission(t *testing.T) {
	for _, writer := range []string{"deferred legacy disk policies", "deferred v8 disk policies"} {
		t.Run(writer, func(t *testing.T) {
			pluginsDir := writeManagementPluginFile(t, "sample")
			pluginPath, err := pluginFilePath(pluginsDir, "sample")
			if err != nil || pluginPath == "" {
				t.Fatalf("plugin discovery: path=%q err=%v", pluginPath, err)
			}
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			initial := fmt.Sprintf("port: 8317\napi-keys: [K]\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    sample:\n      enabled: true\n", pluginsDir)
			if err := os.WriteFile(configPath, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			host := activeDeleteFreezePlugin(t, cfg, pluginPath)
			originalFile, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RemoteManagement.AllowRemote = true
			h := &Handler{cfg: cfg, configFilePath: configPath, pluginHost: host, envSecret: "pw", failedAttempts: map[string]*attemptInfo{}}
			admitted, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			router := gin.New()
			group := router.Group("/v8/management")
			group.Use(h.Middleware(), func(c *gin.Context) {
				c.Set(ConfigV8ContextKey, true)
				if c.Request.Method == http.MethodDelete {
					// The deletion passed admission before a config writer installs policies.
					close(admitted)
					<-resume
				}
				c.Next()
			})
			group.DELETE("/plugins/:id", h.DeletePlugin)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/v8/management/plugins/sample", nil)
			req.Header.Set("Authorization", "Bearer pw")
			go func() {
				defer close(done)
				router.ServeHTTP(rec, req)
			}()
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
				<-done
			}()
			select {
			case <-admitted:
			case <-time.After(5 * time.Second):
				t.Fatal("deletion did not reach the post-admission barrier")
			}

			digest := config.APIKeyDigest("K")
			desired := initial + "api-key-policies:\n  - key-sha256: " + digest + "\n"
			if writer == "deferred v8 disk policies" {
				desired = initial + "access:\n  api-keys: [K]\n  api-key-policies:\n    - key-sha256: " + digest + "\n"
			}
			// Policy activation is deferred to restart; installing desired policies
			// on disk must not detach an already-serving plugin.
			if err := os.WriteFile(configPath, []byte(desired), 0o600); err != nil {
				t.Fatal(err)
			}
			desiredDisk, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			runtimeConfig := h.cfg
			close(resume)
			<-done

			disk, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			file, errReadFile := os.ReadFile(pluginPath)
			_, configured := h.cfg.Plugins.Configs["sample"]
			loaded, serving := host.PluginLoaded("sample"), activeDeleteFreezePluginServing(host)
			t.Logf("loaded=%t serving=%t", loaded, serving)
			t.Logf("status=%d file_intact=%t config_intact=%t disk_unchanged=%t body=%s", rec.Code, errReadFile == nil && bytes.Equal(file, originalFile), configured, bytes.Equal(disk, desiredDisk), rec.Body.String())
			if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"`+errPolicyConfigFrozen+`"}` {
				t.Fatalf("delete refusal: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Equal(disk, desiredDisk) || h.cfg != runtimeConfig || !configured {
				t.Fatal("refused deletion changed disk or runtime plugin configuration")
			}
			if !loaded || !serving {
				t.Error("refused deletion unloaded the active plugin or stopped its resource service")
			}
			if errReadFile != nil || !bytes.Equal(file, originalFile) {
				t.Fatalf("refused deletion removed or changed plugin file: %v", errReadFile)
			}
		})
	}
}

// Compile a tiny native plugin so this test exercises real load, serve and unload
// behavior instead of injecting host internals or mocking PluginBusy.
func activeDeleteFreezePlugin(t *testing.T, cfg *config.Config, pluginPath string) *pluginhost.Host {
	t.Helper()
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native plugin regression requires cc")
	}
	source := filepath.Join(t.TempDir(), "plugin.c")
	if err := os.WriteFile(source, []byte(activeDeleteFreezePluginSource), 0o600); err != nil {
		t.Fatal(err)
	}
	flag := "-shared"
	if runtime.GOOS == "darwin" {
		flag = "-dynamiclib"
	}
	if output, err := exec.Command(compiler, flag, "-fPIC", "-o", pluginPath, source).CombinedOutput(); err != nil {
		t.Fatalf("build native plugin: %v\n%s", err, output)
	}
	host := pluginhost.New()
	t.Cleanup(host.ShutdownAll)
	host.ApplyConfig(context.Background(), cfg)
	host.RegisterManagementRoutes(context.Background(), nil)
	if !host.PluginLoaded("sample") || !activeDeleteFreezePluginServing(host) {
		t.Fatal("fixture plugin is not loaded and serving")
	}
	return host
}

func activeDeleteFreezePluginServing(host *pluginhost.Host) bool {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v0/resource/plugins/sample/status", nil)
	return host.ServeResourceHTTP(rec, req) && rec.Code == http.StatusOK && rec.Body.String() == "serving"
}

const activeDeleteFreezePluginSource = `
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct { void *ptr; size_t len; } buffer;
typedef struct {
    uint32_t abi_version;
    void *host_ctx;
    int (*call)(void *, const char *, const uint8_t *, size_t, buffer *);
    void (*free_buffer)(void *, size_t);
} host_api;
typedef struct {
    uint32_t abi_version;
    int (*call)(const char *, const uint8_t *, size_t, buffer *);
    void (*free_buffer)(void *, size_t);
    void (*shutdown)(void);
} plugin_api;
static int call(const char *method, const uint8_t *request, size_t len, buffer *response) {
    const char *text = "{\"ok\":true,\"result\":{}}";
    if (!strcmp(method, "plugin.register") || !strcmp(method, "plugin.reconfigure"))
        text = "{\"ok\":true,\"result\":{\"schema_version\":1,\"metadata\":{\"Name\":\"sample\",\"Version\":\"0.1.0\",\"Author\":\"test\",\"GitHubRepository\":\"https://example.invalid/sample\"},\"capabilities\":{\"management_api\":true}}}";
    else if (!strcmp(method, "management.register"))
        text = "{\"ok\":true,\"result\":{\"resources\":[{\"Path\":\"/status\"}]}}";
    else if (!strcmp(method, "management.handle"))
        text = "{\"ok\":true,\"result\":{\"StatusCode\":200,\"Body\":\"c2VydmluZw==\"}}";
    response->len = strlen(text);
    response->ptr = malloc(response->len);
    if (!response->ptr) return 1;
    memcpy(response->ptr, text, response->len);
    (void)request; (void)len;
    return 0;
}
static void free_buffer(void *ptr, size_t len) { (void)len; free(ptr); }
static void shutdown_plugin(void) {}
int cliproxy_plugin_init(const host_api *host, plugin_api *plugin) {
    (void)host;
    plugin->abi_version = 1;
    plugin->call = call;
    plugin->free_buffer = free_buffer;
    plugin->shutdown = shutdown_plugin;
    return 0;
}
`
