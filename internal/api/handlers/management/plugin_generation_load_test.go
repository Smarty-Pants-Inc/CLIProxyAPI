//go:build cgo && linux

package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestPluginGenerationWatcherApplyDuringDelete(t *testing.T) {
	h, host, _, entered, release, callDone := deleteDrainFixture(t)
	<-entered
	h.SetPluginHost(host)
	old := h.cfg.CloneForRuntime()
	reloadDone := make(chan struct{})
	h.SetConfigReloadHook(func(ctx context.Context, cfg *config.Config) { host.ApplyConfig(ctx, cfg); close(reloadDone) })
	leaseTaken := make(chan struct{})
	host.SetConfigApplyLeaseSource(func(cfg *config.Config) func() bool {
		guard := h.pluginConfigApplyLease(cfg)
		close(leaseTaken)
		return guard
	})
	deleteDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { deleteDone <- generationRequest(h, http.MethodDelete, "sample") }()
	for {
		h.mu.Lock()
		deleting := h.pluginsDeleting["sample"]
		h.mu.Unlock()
		if deleting {
			break
		}
		runtime.Gosched()
	}
	applyDone := make(chan struct{})
	go func() { defer close(applyDone); host.ApplyConfig(context.Background(), old) }()
	<-leaseTaken // The direct watcher load took its lease while DELETE owns applyMu.
	release()
	<-callDone
	deleted := <-deleteDone
	<-applyDone
	waitForReloadDone(t, reloadDone)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
	if host.PluginLoaded("sample") || host.PluginRegistered("sample") {
		t.Fatal("queued watcher load resurrected deleted plugin")
	}
	t.Log("direct watcher apply queued behind DELETE: stale lease discarded after tombstone clears")
}

func TestPluginGenerationConfigLoadOutlivesDelete(t *testing.T) {
	h, host, _, _ := generationInstallFixture(t)
	// Retain a lower-priority historical artifact. DELETE removes the selected
	// artifact; a stale enabled config must not load this remaining candidate.
	selected, err := pluginFilePath(h.cfg.Plugins.Dir, "sample")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(selected)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(h.cfg.Plugins.Dir, "sample"+managementPluginExtension(runtime.GOOS))
	if err := os.WriteFile(fallback, data, 0o600); err != nil {
		t.Fatal(err)
	}
	entered, resume, oldDone, newDone := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.SetConfigReloadHook(func(ctx context.Context, cfg *config.Config) {
		if _, enabled := cfg.Plugins.Configs["sample"]; enabled {
			once.Do(func() { close(entered); <-resume })
			host.ApplyConfig(ctx, cfg)
		} else {
			host.ApplyConfig(ctx, cfg)
			close(newDone)
		}
	})
	h.mu.Lock()
	old := h.reloadSnapshotConfigLocked()
	h.mu.Unlock()
	go func() { defer close(oldDone); h.reloadConfigAfterManagementSave(context.Background(), old) }()
	<-entered
	deleted := generationRequest(h, http.MethodDelete, "sample")
	close(resume)
	<-oldDone
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", deleted.Code, deleted.Body.String())
	}
	waitForReloadDone(t, newDone)
	h.mu.Lock()
	_, configured := h.cfg.Plugins.Configs["sample"]
	h.mu.Unlock()
	if configured || host.PluginLoaded("sample") || host.PluginRegistered("sample") {
		t.Fatalf("stale config loaded after delete: configured=%t loaded=%t registered=%t", configured, host.PluginLoaded("sample"), host.PluginRegistered("sample"))
	}
	t.Log("config apply admitted before DELETE, resumed after DELETE: no re-enable")
}
