package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// Retain fixtures; do not arrange implicit deletion of file-backed state.
func TestWatcherRepeatedAtomicPublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "watcher-atomic-publication-")
	if err != nil {
		t.Fatal(err)
	}
	authDir := filepath.Join(dir, "auths")
	if err = os.Mkdir(authDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	source := func(retry int) []byte {
		return []byte(fmt.Sprintf("auth-dir: %q\nplugins:\n  dir: %q\nrequest-retry: %d\n", authDir, filepath.Join(dir, "plugins"), retry))
	}
	if err = os.WriteFile(path, source(1), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	changes := make(chan int, 16)
	w, err := NewWatcher(path, authDir, func(cfg *config.Config) { changes <- cfg.RequestRetry })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() {
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	}()
	w.SetConfig(cfg)
	if err = w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for _, retry := range []int{2, 3} {
		file, errTemp := os.CreateTemp(dir, ".operator-*.tmp")
		if errTemp != nil {
			t.Fatal(errTemp)
		}
		if _, err = file.Write(source(retry)); err != nil {
			t.Fatal(err)
		}
		if err = file.Sync(); err != nil {
			t.Fatal(err)
		}
		if err = file.Close(); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(file.Name(), path); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(5 * time.Second)
	wait:
		for {
			select {
			case got := <-changes:
				if got == retry {
					break wait
				}
			case <-deadline:
				t.Fatalf("watcher lost atomic publication request-retry=%d", retry)
			}
		}
	}
}
