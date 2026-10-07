package watcher

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestWatcherFailedApplicationRemainsUnobserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	baseline := []byte("request-retry: 1\n")
	updated := []byte("request-retry: 2\n")
	if err := config.WriteConfigAtomic(path, baseline); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	succeed := false
	apply := func(*config.Config) bool { calls++; return succeed }
	w, err := NewWatcher(path, dir, func(cfg *config.Config) { apply(cfg) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	}()
	// Also executable against the original notification-only callback API.
	if observer, ok := any(w).(interface {
		SetReloadResultCallback(func(*config.Config) bool)
	}); ok {
		observer.SetReloadResultCallback(apply)
	}
	w.SetConfig(cfg)
	w.ReloadConfigIfChanged()
	prior := append([]byte(nil), w.oldConfigYaml...)
	if err = config.WriteConfigAtomic(path, updated); err != nil {
		t.Fatal(err)
	}
	w.ReloadConfigIfChanged()
	if w.lastConfigHash != "" {
		t.Error("failed application recorded a source observation")
	}
	if !bytes.Equal(w.oldConfigYaml, prior) {
		t.Error("failed application advanced the applied snapshot used for retry decisions")
	}
	succeed = true
	w.ReloadConfigIfChanged()
	if calls != 3 {
		t.Errorf("unchanged failed source not retried: calls=%d want=3", calls)
	}
	if w.lastConfigHash == "" {
		t.Error("successful retry was not observed")
	}
	w.ReloadConfigIfChanged()
	if calls != 3 {
		t.Error("ordinary successful source was not skipped")
	}
}
