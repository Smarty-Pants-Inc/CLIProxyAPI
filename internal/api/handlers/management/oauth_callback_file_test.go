package management

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The OAuth callback file carries the authorization code and state, so it is
// written through misc.WriteAuthFileAtomic: owner-only, no leftover temp files
// (CLIProxyAPI#111 review).
func TestWriteOAuthCallbackFileUsesAtomicOwnerOnlyWriter(t *testing.T) {
	authDir := t.TempDir()
	state := "callback-file-state"

	// A stale callback with a wider mode must be replaced by an owner-only file.
	stalePath := filepath.Join(authDir, ".oauth-anthropic-"+state+".oauth")
	if errWrite := os.WriteFile(stalePath, []byte(`{"code":"stale"}`), 0o644); errWrite != nil {
		t.Fatalf("seed stale callback file: %v", errWrite)
	}
	if errChmod := os.Chmod(stalePath, 0o644); errChmod != nil {
		t.Fatalf("chmod stale callback file: %v", errChmod)
	}

	path, err := WriteOAuthCallbackFile(authDir, "anthropic", state, "auth-code-1", "")
	if err != nil {
		t.Fatalf("WriteOAuthCallbackFile: %v", err)
	}
	if path != stalePath {
		t.Fatalf("callback path = %q, want %q", path, stalePath)
	}

	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat callback file: %v", errStat)
	}
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0o600 {
			t.Fatalf("callback file mode = %#o, want 0600", mode)
		}
	}

	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read callback file: %v", errRead)
	}
	var payload oauthCallbackFilePayload
	if errUnmarshal := json.Unmarshal(raw, &payload); errUnmarshal != nil {
		t.Fatalf("decode callback file: %v; raw=%s", errUnmarshal, raw)
	}
	if payload.Code != "auth-code-1" || payload.State != state || payload.Error != "" {
		t.Fatalf("callback payload = %+v, want code auth-code-1 and state %q", payload, state)
	}

	entries, errReadDir := os.ReadDir(authDir)
	if errReadDir != nil {
		t.Fatalf("read auth dir: %v", errReadDir)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("auth dir entries = %v, want only %q (no temp files left)", names, filepath.Base(path))
	}
}
