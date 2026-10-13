//go:build !windows

package xai

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Token files go through misc.WriteAuthFileAtomic: owner-only even when a legacy
// 0644 file is replaced under umask 022, and no temp leftovers.
func TestSaveTokenToFileOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := filepath.Join(t.TempDir(), "auths")
	path := filepath.Join(dir, "xai-user.json")
	storage := &TokenStorage{AccessToken: "fake-access"}
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("first SaveTokenToFile: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("second SaveTokenToFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %v, %v; want 0600", info, err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("created token dir = %v, %v; want 0700", dirInfo, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dir entries = %v, %v; want only the token file", entries, err)
	}
}
