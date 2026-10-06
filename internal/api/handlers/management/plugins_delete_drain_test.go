//go:build cgo && linux

package management

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
)

func TestDeletePluginBoundedDrain(t *testing.T) {
	for _, scenario := range []string{"deadline", "disconnect", "freeze during drain", "success", "unrelated config write"} {
		t.Run(scenario, func(t *testing.T) {
			h, host, pluginPath, entered, release, callDone := deleteDrainFixture(t)
			router := gin.New()
			router.DELETE("/plugins/:id", h.DeletePlugin)
			router.GET("/plugins/:id/config", h.GetPluginConfig)
			router.PUT("/plugins/:id/config", h.PutPluginConfig)
			router.PATCH("/plugins/:id/config", h.PatchPluginConfig)
			router.PATCH("/plugins/:id/enabled", h.PatchPluginEnabled)
			router.Any("/config/*path", h.ConfigV8)
			originalFile, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			originalDisk, err := os.ReadFile(h.configFilePath)
			if err != nil {
				t.Fatal(err)
			}
			// The native call ignores its Go context and stays active until released.
			<-entered
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), 400*time.Millisecond)
				defer cancel()
			}
			req := httptest.NewRequest(http.MethodDelete, "/plugins/sample", nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { defer close(done); router.ServeHTTP(rec, req) }()
			defer func() { release(); <-callDone; <-done }()

			// Observe the call tombstone through the real host, without timing sleeps.
			gateCtx, gateCancel := context.WithTimeout(context.Background(), time.Second)
			defer gateCancel()
			for {
				probe := httptest.NewRecorder()
				handled := host.ServeResourceHTTP(probe, httptest.NewRequest(http.MethodGet, "/v0/resource/plugins/sample/status", nil).WithContext(gateCtx))
				if !handled || probe.Code != http.StatusOK {
					break
				}
				select {
				case <-done:
					t.Fatalf("DELETE completed before drain was observed: %d %s", rec.Code, rec.Body.String())
				case <-gateCtx.Done():
					t.Fatal("new plugin calls were not refused during deletion")
				default:
				}
			}
			// Reads must not wait behind the active call's drain. Baseline holds h.mu
			// here indefinitely; release the call on failure so no work is left running.
			probeDone := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				probe := httptest.NewRecorder()
				router.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/plugins/sample/config", nil))
				probeDone <- probe
			}()
			select {
			case probe := <-probeDone:
				if probe.Code != http.StatusOK {
					t.Fatalf("concurrent read: %d %s", probe.Code, probe.Body.String())
				}
			case <-time.After(time.Second):
				release()
				<-callDone
				<-done
				<-probeDone
				t.Fatal("management read blocked behind stuck DELETE drain")
			}

			for _, write := range []struct{ method, path, body string }{
				{http.MethodDelete, "/plugins/sample", ""},
				{http.MethodPut, "/plugins/sample/config", `{\"enabled\":true}`},
				{http.MethodPatch, "/plugins/sample/config", `{\"enabled\":true}`},
				{http.MethodPatch, "/plugins/sample/enabled", `{\"enabled\":false}`},
				{http.MethodPatch, "/config/plugins/configs/sample", `{\"enabled\":false}`},
			} {
				probe := httptest.NewRecorder()
				router.ServeHTTP(probe, httptest.NewRequest(write.method, write.path, strings.NewReader(strings.ReplaceAll(write.body, `\"`, `"`))))
				if probe.Code != http.StatusConflict {
					t.Fatalf("tombstone write %s %s: %d %s", write.method, write.path, probe.Code, probe.Body.String())
				}
			}
			if scenario == "unrelated config write" {
				reloaded := make(chan struct{})
				// Observe the asynchronous save hook without reconfiguring the native test
				// fixture; this assertion concerns management write admission during drain.
				h.SetConfigReloadHook(func(context.Context, *config.Config) { close(reloaded) })
				probe := httptest.NewRecorder()
				router.ServeHTTP(probe, httptest.NewRequest(http.MethodPut, "/config/requests/proxy-url", strings.NewReader(`"direct"`)))
				if probe.Code != http.StatusOK {
					t.Fatalf("unrelated config write: %d %s", probe.Code, probe.Body.String())
				}
				<-reloaded
				originalDisk, err = os.ReadFile(h.configFilePath)
				if err != nil {
					t.Fatal(err)
				}
			}
			wantStatus := http.StatusOK
			switch scenario {
			case "deadline":
				wantStatus = http.StatusGatewayTimeout
			case "disconnect", "unrelated config write":
				cancel()
				wantStatus = http.StatusServiceUnavailable
			case "freeze during drain":
				originalDisk = append(originalDisk, []byte("access:\n  api-key-policies: []\n")...)
				if err := os.WriteFile(h.configFilePath, originalDisk, 0o600); err != nil {
					t.Fatal(err)
				}
				wantStatus = http.StatusConflict
				release()
			case "success":
				release()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("DELETE did not return within the request drain bound")
			}
			if rec.Code != wantStatus {
				t.Fatalf("DELETE: got %d want %d: %s", rec.Code, wantStatus, rec.Body.String())
			}
			loaded := host.PluginLoaded("sample")
			_, configured := h.cfg.Plugins.Configs["sample"]
			file, errFile := os.ReadFile(pluginPath)
			disk, errDisk := os.ReadFile(h.configFilePath)
			if errDisk != nil {
				t.Fatal(errDisk)
			}
			if scenario == "success" {
				if loaded || configured || !os.IsNotExist(errFile) {
					t.Fatal("successful deletion retained plugin state")
				}
			} else {
				if !configured || errFile != nil || !bytes.Equal(file, originalFile) || !bytes.Equal(disk, originalDisk) {
					t.Fatal("refused deletion changed plugin file/config")
				}
				if scenario == "freeze during drain" {
					if loaded {
						t.Fatal("mid-drain freeze should retain file/config but leave plugin unloaded")
					}
				} else {
					if !loaded || !activeDeleteFreezePluginServing(host) {
						t.Fatal("failed drain did not restore loaded and serving plugin")
					}
				}
			}
			t.Logf("scenario=%s status=%d loaded=%t configured=%t", scenario, rec.Code, loaded, configured)
		})
	}
}

// Exercise the server's named timeout with no deadline supplied by the caller.
func TestDeletePluginServerDrainTimeout(t *testing.T) {
	h, host, _, entered, release, callDone := deleteDrainFixture(t)
	<-entered
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: "sample"}}
	c.Request = httptest.NewRequest(http.MethodDelete, "/plugins/sample", nil)
	done := make(chan struct{})
	started := time.Now()
	go func() { defer close(done); h.DeletePlugin(c) }()
	defer func() { release(); <-callDone; <-done }()
	select {
	case <-done:
	case <-time.After(pluginDeleteDrainTimeout + 5*time.Second):
		t.Fatal("server drain timeout was not honored")
	}
	if rec.Code != http.StatusGatewayTimeout || !host.PluginLoaded("sample") || !activeDeleteFreezePluginServing(host) {
		t.Fatalf("server deadline: status=%d loaded=%t body=%s", rec.Code, host.PluginLoaded("sample"), rec.Body.String())
	}
	t.Logf("server timeout=%s elapsed=%s status=%d loaded=true", pluginDeleteDrainTimeout, time.Since(started), rec.Code)
}

func TestDeletePluginHTTPDisconnectCancelsDrain(t *testing.T) {
	h, host, _, entered, release, callDone := deleteDrainFixture(t)
	<-entered
	serverDone := make(chan int, 1)
	router := gin.New()
	router.DELETE("/plugins/:id", func(c *gin.Context) { h.DeletePlugin(c); serverDone <- c.Writer.Status() })
	server := httptest.NewServer(router)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, server.URL+"/plugins/sample", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan error, 1)
	go func() {
		response, err := server.Client().Do(req)
		if response != nil {
			_ = response.Body.Close()
		}
		clientDone <- err
	}()
	// Observe deletion admission through its host call gate before disconnecting.
	gateCtx, gateCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer gateCancel()
	for {
		probe := httptest.NewRecorder()
		if !host.ServeResourceHTTP(probe, httptest.NewRequest(http.MethodGet, "/v0/resource/plugins/sample/status", nil).WithContext(gateCtx)) || probe.Code != http.StatusOK {
			break
		}
		if gateCtx.Err() != nil {
			cancel()
			<-clientDone
			release()
			<-callDone
			<-serverDone
			t.Fatal("HTTP DELETE never began draining")
		}
	}
	cancel()
	if err := <-clientDone; err == nil {
		t.Error("disconnected client did not report cancellation")
	}
	defer func() { release(); <-callDone }()
	select {
	case status := <-serverDone:
		if status != http.StatusServiceUnavailable {
			t.Fatalf("disconnect drain status=%d", status)
		}
	case <-time.After(2 * time.Second):
		release()
		<-callDone
		<-serverDone
		t.Fatal("client disconnect did not cancel server drain")
	}
	if !host.PluginLoaded("sample") || !activeDeleteFreezePluginServing(host) {
		t.Fatal("HTTP disconnect did not restore plugin state")
	}
	t.Log("HTTP client disconnected: server status=503, plugin loaded and serving")
}

func deleteDrainFixture(t *testing.T) (*Handler, *pluginhost.Host, string, <-chan struct{}, func(), <-chan struct{}) {
	t.Helper()
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("native drain regression requires cc")
	}
	startedR, startedW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = startedR.Close(); _ = startedW.Close(); _ = releaseR.Close(); _ = releaseW.Close() })
	dir := writeManagementPluginFile(t, "sample")
	path, err := pluginFilePath(dir, "sample")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(activeDeleteFreezePluginSource, "#include <stdint.h>", "#include <stdint.h>\n#include <unistd.h>", 1)
	source = strings.Replace(source, "const char *text =", fmt.Sprintf("if (!strcmp(method, \"management.handle\") && len && strstr((const char *)request, \"/blocked\")) { char b; write(%d, \"s\", 1); read(%d, &b, 1); }\n    const char *text =", startedW.Fd(), releaseR.Fd()), 1)
	// ABI request bytes need not be NUL-terminated; search within the request length.
	source = strings.Replace(source, "len && strstr((const char *)request, \"/blocked\")", "len && memmem(request, len, \"/blocked\", 8)", 1)
	source = strings.Replace(source, `[{\"Path\":\"/status\"}]`, `[{\"Path\":\"/status\"},{\"Path\":\"/blocked\"}]`, 1)
	source = "#define _GNU_SOURCE\n" + source
	sourcePath := filepath.Join(t.TempDir(), "plugin.c")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(compiler, "-shared", "-fPIC", "-o", path, sourcePath).CombinedOutput(); err != nil {
		t.Fatalf("compile plugin: %v %s", err, out)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	initial := fmt.Sprintf("port: 8317\nplugins:\n  enabled: true\n  dir: %q\n  configs:\n    sample:\n      enabled: true\n", dir)
	if err := os.WriteFile(configPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	host := pluginhost.New()
	t.Cleanup(host.ShutdownAll)
	host.ApplyConfig(context.Background(), cfg)
	host.RegisterManagementRoutes(context.Background(), nil)
	if !activeDeleteFreezePluginServing(host) {
		t.Fatal("plugin fixture is not serving")
	}
	entered, callDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(callDone)
		host.ServeResourceHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v0/resource/plugins/sample/blocked", nil))
	}()
	go func() { var b [1]byte; _, _ = io.ReadFull(startedR, b[:]); close(entered) }()
	released := false
	release := func() {
		if !released {
			released = true
			_, _ = releaseW.Write([]byte("r"))
		}
	}
	t.Cleanup(func() { release(); <-callDone; <-entered })
	return &Handler{cfg: cfg, configFilePath: configPath, pluginHost: host}, host, path, entered, release, callDone
}
