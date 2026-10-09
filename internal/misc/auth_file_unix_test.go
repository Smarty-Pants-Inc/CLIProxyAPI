//go:build !windows

package misc

import (
	"os"
	"path/filepath"
	"testing"
)

func authFileRenameErrorDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "auth")
}

func TestRestrictAuthDirForStartupDoesNotChangePOSIXFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "legacy.json")
	if err := os.WriteFile(file, []byte("synthetic-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, link, filepath.Join(dir, "missing")} {
		if err := RestrictAuthDirForStartup(path); err != nil {
			t.Fatalf("POSIX startup helper must remain a no-op: %v", err)
		}
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("POSIX file mode changed: %v, %v", info, err)
	}
	if target, err := os.Readlink(link); err != nil || target != file {
		t.Fatalf("POSIX symlink changed: %q, %v", target, err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "synthetic-token" {
		t.Fatalf("POSIX token content changed: %q, %v", data, err)
	}
}
