//go:build !windows

package codex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSaveTokenToFileOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })

	dir := filepath.Join(t.TempDir(), "auths")
	path := filepath.Join(dir, "codex-user@example.com.json")
	storage := &CodexTokenStorage{AccessToken: "fake-access", RefreshToken: "fake-refresh", Email: "user@example.com"}
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("first SaveTokenToFile: %v", err)
	}
	// A legacy world-readable token file is replaced with an owner-only one.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// This is an intentional re-login, not a stale runtime snapshot save.
	storage.ReplaceCredentials = true
	storage.AccessToken = "fake-access-2"
	if err := storage.SaveTokenToFile(path); err != nil {
		t.Fatalf("second SaveTokenToFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("token file mode = %#o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("created token dir mode = %#o, want 0700", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 || entries[0].Name() != filepath.Base(path) || entries[1].Name() != filepath.Base(path)+".lock" {
		t.Fatalf("dir entries = %v, %v; want token and persistent inter-process lock only", entries, err)
	}
	lockInfo, errLock := os.Stat(path + ".lock")
	if errLock != nil || !lockInfo.Mode().IsRegular() || lockInfo.Size() != 0 || lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("lock file = %v, %v; want empty owner-only regular file", lockInfo, errLock)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token: %v", err)
	}
	var saved map[string]any
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatalf("token is not valid JSON: %v", err)
	}
	if saved["access_token"] != "fake-access-2" || saved["type"] != "codex" {
		t.Fatalf("saved token = %v", saved)
	}
}
