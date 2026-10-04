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

func TestAtomicConfigPublicationsReloadRepeatedly(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("port: 8080\nauth-dir: %q\n", authDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	reloads := make(chan int, 8)
	w, err := NewWatcher(path, authDir, func(cfg *config.Config) { reloads <- cfg.Port })
	if err != nil {
		t.Fatal(err)
	}
	w.SetConfig(initial)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	}()
	if err = w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitPort := func(want int) {
		t.Helper()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case got := <-reloads:
				if got == want {
					return
				}
			case <-deadline.C:
				t.Fatalf("atomic publication of port %d was not reloaded", want)
			}
		}
	}
	waitPort(8080)
	for _, port := range []int{8081, 8082} {
		cfg, errLoad := config.LoadConfig(path)
		if errLoad != nil {
			t.Fatal(errLoad)
		}
		cfg.Port = port
		if errSave := config.SaveConfigPreserveComments(path, cfg); errSave != nil {
			t.Fatal(errSave)
		}
		waitPort(port)
	}
}

func TestReloadHashTracksSnapshotNotLaterPublication(t *testing.T) {
	dir := t.TempDir()
	authDir := filepath.Join(dir, "auth")
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("port: 8081\nauth-dir: %q\n", authDir)), 0o600); err != nil {
		t.Fatal(err)
	}
	var ports []int
	w, err := NewWatcher(path, authDir, func(cfg *config.Config) {
		ports = append(ports, cfg.Port)
		if cfg.Port == 8081 {
			next := cfg.CloneForRuntime()
			next.Port = 8082
			if errSave := config.SaveConfigPreserveComments(path, next); errSave != nil {
				t.Error(errSave)
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errStop := w.Stop(); errStop != nil {
			t.Error(errStop)
		}
	}()
	w.reloadConfigIfChanged()
	w.reloadConfigIfChanged()
	if len(ports) != 2 || ports[0] != 8081 || ports[1] != 8082 {
		t.Fatalf("later config was marked observed without reload: %v", ports)
	}
}
