package cliproxy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func TestEnsureAuthDirAppliesPlatformRestriction(t *testing.T) {
	denied := errors.New("platform restriction denied")
	for _, tc := range []struct {
		name     string
		existing bool
		cause    error
	}{
		{name: "new_denied", cause: denied},
		{name: "existing_denied", existing: true, cause: denied},
		{name: "new_allowed"},
		{name: "existing_allowed", existing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "auths")
			if tc.existing {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			}
			original := restrictAuthDir
			t.Cleanup(func() { restrictAuthDir = original })
			calls := 0
			restrictAuthDir = func(path string) error {
				calls++
				if path != dir {
					t.Fatalf("restriction path = %q, want %q", path, dir)
				}
				info, err := os.Stat(path)
				if err != nil || !info.IsDir() {
					t.Fatalf("restriction requires an existing directory: %v", err)
				}
				return tc.cause
			}
			s := &Service{cfg: &config.Config{AuthDir: dir}}
			err := s.ensureAuthDir()
			if calls != 1 {
				t.Fatalf("restriction calls = %d, want 1", calls)
			}
			if tc.cause == nil {
				if err != nil {
					t.Fatalf("ensureAuthDir rejected a successful restriction: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("ensureAuthDir succeeded despite a failed platform restriction")
			}
			if err == tc.cause || !errors.Is(err, tc.cause) || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "owner-only") {
				t.Fatalf("error %q does not wrap the cause with directory and owner-only context", err)
			}
		})
	}
}

func TestEnsureAuthDirRejectsNonDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "auths")
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	original := restrictAuthDir
	t.Cleanup(func() { restrictAuthDir = original })
	restrictAuthDir = func(string) error {
		t.Fatal("platform restriction must not run on a non-directory")
		return nil
	}
	s := &Service{cfg: &config.Config{AuthDir: dir}}
	if err := s.ensureAuthDir(); err == nil || !strings.Contains(err.Error(), dir) || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("ensureAuthDir error = %v, want non-directory diagnostic naming path", err)
	}
}

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

// A permissive auth dir that cannot be tightened refuses startup with an error
// naming the directory and the required mode; an owner-only dir never needs
// the chmod and starts even when chmod would fail.
func TestEnsureAuthDirFailsClosedWhenTighteningFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	original := chmodAuthDir
	t.Cleanup(func() { chmodAuthDir = original })
	chmodAuthDir = func(string, os.FileMode) error { return os.ErrPermission }

	dir := filepath.Join(t.TempDir(), "auths")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	s := &Service{cfg: &config.Config{AuthDir: dir}}
	err := s.ensureAuthDir()
	if err == nil {
		t.Fatal("ensureAuthDir succeeded on a 0755 auth dir it could not tighten")
	}
	if msg := err.Error(); !strings.Contains(msg, dir) || !strings.Contains(msg, "0700") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("error %q does not name the directory, the required 0700 mode and the cause", msg)
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := s.ensureAuthDir(); err != nil {
		t.Fatalf("owner-only auth dir must start without chmod: %v", err)
	}
}
