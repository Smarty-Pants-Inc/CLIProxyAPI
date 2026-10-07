package watcher

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestWatcherRecordsExactCapturedSnapshot(t *testing.T) {
	dir, err := os.MkdirTemp("", "watcher-exact-snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	a := []byte("auth-dir: " + fmt.Sprintf("%q", filepath.Join(dir, "auths")) + "\nrequest-retry: 1\n")
	b := []byte("auth-dir: " + fmt.Sprintf("%q", filepath.Join(dir, "auths")) + "\nrequest-retry: 2\n")
	c := []byte("auth-dir: " + fmt.Sprintf("%q", filepath.Join(dir, "auths")) + "\nrequest-retry: 3\n")
	if err = os.Mkdir(filepath.Join(dir, "auths"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, a, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	var applied []int
	w, err := NewWatcher(path, cfg.AuthDir, func(cfg *config.Config) { applied = append(applied, cfg.RequestRetry) })
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Stop() }()
	w.SetConfig(cfg)
	if err = config.WriteConfigAtomic(path, b); err != nil {
		t.Fatal(err)
	}
	captured, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A legitimate revert after observation must not change which snapshot is applied.
	if err = config.WriteConfigAtomic(path, a); err != nil {
		t.Fatal(err)
	}
	if !w.reloadConfig(captured) {
		t.Fatal("captured snapshot reload failed")
	}
	if err = config.WriteConfigAtomic(path, c); err != nil {
		t.Fatal(err)
	}
	w.ReloadConfigIfChanged()
	if len(applied) != 2 || applied[0] != 2 || applied[1] != 3 {
		t.Fatalf("applied snapshots = %v, want [2 3]", applied)
	}
}

func TestWatcherPublicationDuringRuntimeApply(t *testing.T) {
	dir, err := os.MkdirTemp("", "watcher-observation-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	source := func(retry int) []byte {
		return []byte(fmt.Sprintf("auth-dir: %q\nplugins:\n  dir: %q\nrequest-retry: %d\n", filepath.Join(dir, "auths"), filepath.Join(dir, "plugins"), retry))
	}
	if err = os.Mkdir(filepath.Join(dir, "auths"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, source(1), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(chan struct{})
	release := make(chan struct{})
	observed := make(chan int, 2)
	w, err := NewWatcher(path, cfg.AuthDir, func(cfg *config.Config) {
		if cfg.RequestRetry == 2 {
			close(loaded)
			<-release
		}
		observed <- cfg.RequestRetry
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	}()
	w.SetConfig(cfg)
	if err = config.WriteConfigAtomic(path, source(2)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { w.ReloadConfigIfChanged(); close(done) }()
	select {
	case <-loaded:
	case <-time.After(5 * time.Second):
		close(release)
		<-done
		t.Fatal("runtime apply did not reach gate")
	}
	// Complete a newer publication after load, during the older runtime apply.
	errPublish := config.WriteConfigAtomic(path, source(3))
	close(release)
	<-done
	if errPublish != nil {
		t.Fatal(errPublish)
	}
	if got := <-observed; got != 2 {
		t.Fatalf("first apply=%d", got)
	}
	w.ReloadConfigIfChanged()
	select {
	case got := <-observed:
		if got != 3 {
			t.Fatalf("newer apply=%d", got)
		}
	default:
		t.Fatal("newer publication was incorrectly marked observed without runtime apply")
	}
}
