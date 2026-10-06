//go:build unix

package config

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO supplies the original source bytes to the real LoadConfig path. The
// save mutex gates hash persistence while an external raw writer replaces the
// path with a completed newer revision. No timer or bcrypt timing assumption.
func TestConfigSaveFenceLoadHashConcurrentRewrite(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		name := "unrelated-update"
		if rotated {
			name = "key-rotation"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			type result struct {
				cfg *Config
				err error
			}
			loaded := make(chan result, 1)
			configSaveMu.Lock()
			locked := true
			defer func() {
				if locked {
					configSaveMu.Unlock()
				}
			}()
			go func() {
				cfg, err := LoadConfig(path)
				loaded <- result{cfg, err}
			}()
			// Opening for write is a handshake: LoadConfig has opened the original
			// FIFO for read, so unlinking cannot change the bytes it will parse.
			fifo, err := os.OpenFile(path, os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = fifo.WriteString("port: 8080\nremote-management:\n  secret-key: synthetic-original-secret\n"); err != nil {
				_ = fifo.Close()
				t.Fatal(err)
			}
			if err = fifo.Close(); err != nil {
				t.Fatal(err)
			}
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			secret := "synthetic-original-secret"
			if rotated {
				secret = "synthetic-new-secret"
			}
			newer := []byte("# completed external update\nport: 9090\nremote-management:\n  secret-key: " + secret + "\n")
			if err = os.WriteFile(path, newer, 0600); err != nil {
				t.Fatal(err)
			}
			configSaveMu.Unlock()
			locked = false
			got := <-loaded
			if got.cfg != nil || !errors.Is(got.err, ErrStaleConfig) {
				t.Fatalf("LoadConfig = cfg present %t, err %v; want stale error", got.cfg != nil, got.err)
			}
			if string(fenceRead(t, path)) != string(newer) {
				t.Error("hash persistence overwrote newer source or rotated key")
			}
		})
	}
}
