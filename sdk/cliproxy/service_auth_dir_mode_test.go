package cliproxy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestEnsureAuthDirCreatesOwnerOnlyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := filepath.Join(t.TempDir(), "auths")
	s := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := s.ensureAuthDir(); err != nil {
		t.Fatalf("ensureAuthDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("auth dir mode = %#o, want 0700", got)
	}
}

func TestEnsureAuthDirTightensExistingPermissiveDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	for _, mode := range []os.FileMode{0o755, 0o750, 0o705, 0o777} {
		dir := filepath.Join(t.TempDir(), "auths")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		s := &Service{cfg: &config.Config{AuthDir: dir}}
		if err := s.ensureAuthDir(); err != nil {
			t.Fatalf("ensureAuthDir(%#o): %v", mode, err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("pre-existing %#o auth dir mode = %#o, want 0700", mode, got)
		}
	}
}

func TestEnsureAuthDirKeepsStricterDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := filepath.Join(t.TempDir(), "auths")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	s := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := s.ensureAuthDir(); err != nil {
		t.Fatalf("ensureAuthDir: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o500 {
		t.Fatalf("owner-only auth dir mode = %#o, want unchanged 0500", got)
	}
}
