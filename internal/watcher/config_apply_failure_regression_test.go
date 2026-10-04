package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestFailedRuntimeApplyDoesNotObserveVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("auth-dir: %q\nrequest-retry: 2\n", dir)), 0600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(path, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	}()
	setter, ok := any(w).(interface {
		SetReloadResultCallback(func(*config.Config) bool)
	})
	if !ok {
		t.Fatal("watcher cannot receive runtime application failure")
	}
	attempts := 0
	setter.SetReloadResultCallback(func(*config.Config) bool { attempts++; return attempts > 1 })
	w.reloadConfigIfChanged()
	if w.lastConfigHash != "" || w.config != nil || len(w.oldConfigYaml) != 0 {
		t.Fatal("failed runtime application advanced observed version or comparison snapshot")
	}
	w.reloadConfigIfChanged()
	version, err := config.ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || w.lastConfigHash != version {
		t.Fatalf("failed application was not retried: attempts=%d version=%s", attempts, w.lastConfigHash)
	}
}
