//go:build cgo && linux

package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
)

type generationDownloadBarrier struct {
	responses       fakePluginStoreHTTPClient
	artifact        string
	entered, resume chan struct{}
	once            sync.Once
}

func (b *generationDownloadBarrier) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() == b.artifact {
		b.once.Do(func() { close(b.entered); <-b.resume })
	}
	return b.responses.Do(req)
}

func generationRequest(h *Handler, method, id string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Params = gin.Params{{Key: "id", Value: id}}
	c.Request = httptest.NewRequest(method, "/v8/management/plugins/"+id, nil)
	c.Set(ConfigV8ContextKey, true)
	if method == http.MethodDelete {
		h.DeletePlugin(c)
	} else {
		h.InstallPluginFromStore(c)
	}
	return rec
}

func generationInstallFixture(t *testing.T) (*Handler, *pluginhost.Host, *generationDownloadBarrier, <-chan *config.Config) {
	t.Helper()
	dir := writeManagementPluginFile(t, "sample")
	path, err := pluginFilePath(dir, "sample")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Plugins: config.PluginsConfig{Enabled: true, Dir: dir, Configs: map[string]config.PluginInstanceConfig{"sample": pluginConfigFromYAML(t, "enabled: true\n")}}}
	host := activeDeleteFreezePlugin(t, cfg, path)
	library, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	archive := makeManagementPluginStoreZip(t, "sample"+managementPluginExtension(runtime.GOOS), string(library))
	sum := sha256.Sum256(archive)
	url := "https://downloads.example/sample.zip"
	barrier := &generationDownloadBarrier{artifact: url, entered: make(chan struct{}), resume: make(chan struct{}), responses: fakePluginStoreHTTPClient{
		"https://registry.example/registry.json": []byte(strings.ReplaceAll(string(directRegistryJSON(url, hex.EncodeToString(sum[:]))), "sample-provider", "sample")),
		url:                                      archive,
	}}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("port: 8317\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := config.SaveConfigPreserveComments(configPath, cfg, true); err != nil {
		t.Fatal(err)
	}
	h := &Handler{cfg: cfg, configFilePath: configPath, pluginStoreRegistryURL: "https://registry.example/registry.json", pluginStoreHTTPClient: barrier}
	h.SetPluginHost(host)
	reloaded := make(chan *config.Config, 8)
	h.SetConfigReloadHook(func(ctx context.Context, cfg *config.Config) { host.ApplyConfig(ctx, cfg); reloaded <- cfg })
	return h, host, barrier, reloaded
}

func generationAssertDeleted(t *testing.T, h *Handler, host *pluginhost.Host) {
	t.Helper()
	h.mu.Lock()
	_, configured := h.cfg.Plugins.Configs["sample"]
	dir := h.cfg.Plugins.Dir
	h.mu.Unlock()
	if configured || host.PluginLoaded("sample") || host.PluginRegistered("sample") {
		t.Errorf("plugin resurrected: configured=%t loaded=%t registered=%t", configured, host.PluginLoaded("sample"), host.PluginRegistered("sample"))
	}
	disk, err := config.LoadConfig(h.configFilePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := disk.Plugins.Configs["sample"]; exists {
		t.Error("saved config resurrected plugin")
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			t.Errorf("artifact survived deletion: %s", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPluginGenerationInstallOutlivesDelete(t *testing.T) {
	h, host, barrier, reloaded := generationInstallFixture(t)
	installDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { installDone <- generationRequest(h, http.MethodPost, "sample") }()
	<-barrier.entered
	deleted := generationRequest(h, http.MethodDelete, "sample")
	if deleted.Code != http.StatusOK {
		close(barrier.resume)
		<-installDone
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	close(barrier.resume)
	installed := <-installDone
	if installed.Code == http.StatusOK {
		waitForAsyncReload(t, reloaded)
	}
	generationAssertDeleted(t, h, host)
	if installed.Code != http.StatusConflict {
		t.Errorf("stale install status=%d, want 409: %s", installed.Code, installed.Body.String())
	}
	t.Logf("delete=%d stale_install=%d; no config, runtime or staged artifact", deleted.Code, installed.Code)
}

func TestPluginGenerationStaleInstallPreservesReplacement(t *testing.T) {
	h, host, barrier, reloaded := generationInstallFixture(t)
	oldDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { oldDone <- generationRequest(h, http.MethodPost, "sample") }()
	<-barrier.entered
	deleted := generationRequest(h, http.MethodDelete, "sample")
	if deleted.Code != http.StatusOK {
		close(barrier.resume)
		<-oldDone
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	// The old request already captured its client before reaching the barrier.
	// Let a new request install the same version without releasing the old one.
	h.pluginStoreHTTPClient = barrier.responses
	replacement := generationRequest(h, http.MethodPost, "sample")
	if replacement.Code != http.StatusOK {
		close(barrier.resume)
		<-oldDone
		t.Fatalf("replacement install: %d %s", replacement.Code, replacement.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	close(barrier.resume)
	stale := <-oldDone
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale install: %d %s", stale.Code, stale.Body.String())
	}
	if !host.PluginLoaded("sample") || !host.PluginRegistered("sample") {
		t.Fatal("stale cleanup disturbed replacement runtime")
	}
	h.mu.Lock()
	item, exists := h.cfg.Plugins.Configs["sample"]
	h.mu.Unlock()
	if !exists || !pluginInstanceEnabled(item) {
		t.Fatal("stale cleanup disturbed replacement config")
	}
	target := filepath.Join(h.cfg.Plugins.Dir, runtime.GOOS, runtime.GOARCH, "sample-v0.4.0"+managementPluginExtension(runtime.GOOS))
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("stale cleanup removed replacement artifact: %v", err)
	}
	staged, err := filepath.Glob(filepath.Join(h.cfg.Plugins.Dir, ".install-*"))
	if err != nil || len(staged) != 0 {
		t.Fatalf("staging directories remain: %v %v", staged, err)
	}
	t.Log("delete=200 replacement=200 stale=409; stale cleanup owns only its private stage")
}

func TestPluginGenerationInstallDuringDelete(t *testing.T) {
	h, host, _, entered, release, callDone := deleteDrainFixture(t)
	<-entered
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- generationRequest(h, http.MethodDelete, "sample") }()
	defer func() { release(); <-callDone; <-done }()
	for {
		h.mu.Lock()
		deleting := h.pluginsDeleting["sample"]
		h.mu.Unlock()
		if deleting {
			break
		}
		runtime.Gosched()
	}
	installed := generationRequest(h, http.MethodPost, "sample")
	if installed.Code != http.StatusConflict {
		t.Fatalf("install during delete: %d %s", installed.Code, installed.Body.String())
	}
	if !host.PluginLoaded("sample") {
		t.Fatal("drain fixture unexpectedly unloaded before release")
	}
	t.Log("install during active delete lease: 409")
}

func TestPluginGenerationOrdinaryInstallThenDelete(t *testing.T) {
	h, host, barrier, reloaded := generationInstallFixture(t)
	// The native fixture supplies the archive bytes; start the business lifecycle
	// from a clean, deleted plugin rather than merely updating its old library.
	initialDelete := generationRequest(h, http.MethodDelete, "sample")
	if initialDelete.Code != http.StatusOK {
		t.Fatalf("fixture delete: %d %s", initialDelete.Code, initialDelete.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	generationAssertDeleted(t, h, host)
	close(barrier.resume)
	installed := generationRequest(h, http.MethodPost, "sample")
	if installed.Code != http.StatusOK {
		t.Fatalf("install: %d %s", installed.Code, installed.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	if !host.PluginLoaded("sample") || !host.PluginRegistered("sample") {
		t.Fatal("ordinary install did not load/register plugin")
	}
	deleted := generationRequest(h, http.MethodDelete, "sample")
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
	waitForAsyncReload(t, reloaded)
	generationAssertDeleted(t, h, host)
	t.Log("ordinary install=200, delete=200; config/runtime removed")
}
