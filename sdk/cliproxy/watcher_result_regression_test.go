package cliproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestDefaultWatcherReportsFailedRuntimeApply(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("auth-dir: %q\nrequest-retry: 2\n", dir)), 0600); err != nil {
		t.Fatal(err)
	}
	legacy := 0
	w, err := defaultWatcherFactory(path, dir, func(*config.Config) { legacy++ })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := w.Stop(); err != nil {
			t.Error(err)
		}
	}()
	attempts := 0
	w.SetReloadResultCallback(func(*config.Config) bool { attempts++; return attempts > 1 })
	w.ReloadConfigIfChanged()
	w.ReloadConfigIfChanged()
	w.ReloadConfigIfChanged()
	if attempts != 2 || legacy != 0 {
		t.Fatalf("failure-aware SDK callback not registered: attempts=%d legacy=%d", attempts, legacy)
	}
}
