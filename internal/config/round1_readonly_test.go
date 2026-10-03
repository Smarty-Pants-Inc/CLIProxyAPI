package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRound1ReadOnlyMixedLayoutLoader(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("read-only descriptor probe requires procfs")
	}
	dir, err := os.MkdirTemp(os.Getenv("TMPDIR"), "round1-config-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.yaml")
	const body = "port: 8317\nserver: {port: 8317}\n"
	if err = os.WriteFile(path, []byte(body), 0400); err != nil {
		t.Fatal(err)
	}
	// /proc exposes a readable, non-writable descriptor path (also deterministic as root).
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	readonly := "/proc/self/fd/" + fmt.Sprint(f.Fd())
	cfg, err := LoadConfig(readonly)
	if err != nil {
		t.Fatalf("valid read-only mixed config rejected: %v", err)
	}
	if cfg.Port != 8317 {
		t.Fatalf("canonical port = %d", cfg.Port)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Errorf("optional cleanup mutated read-only file: %s", got)
	}
}
