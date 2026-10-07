package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// When the load-time cleanup cannot be published (here a read-only directory, like
// a single-file bind mount that refuses the rename), loading still succeeds and the
// file is left unchanged.
func TestLoadConfigCleanupWriteFailureIsNotFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	baseline := []byte("debug: false\nport: 8317\ntls: null\nserver:\n  tls:\n    enable: false\n")
	if err := os.WriteFile(path, baseline, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load with unwritable cleanup: %v", err)
	}
	if cfg.Port != 8317 {
		t.Fatalf("port = %d, want 8317", cfg.Port)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, baseline) {
		t.Fatal("config file changed although the cleanup could not be written")
	}
	if !cfg.sourceRevision.matches(baseline) {
		t.Fatal("revision must stay on the unchanged file")
	}
}
