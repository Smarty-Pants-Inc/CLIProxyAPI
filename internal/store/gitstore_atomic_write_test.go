package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The git-backed store writes metadata auth files through the shared atomic
// writer (unique temp + fsync + rename), so a stale fixed "<name>.tmp" left by a
// crashed write cannot block a later save, the replaced file is 0600, and no
// temp file is left beside it (smarty-dev#6359 forward port).
func TestGitTokenStoreSaveWritesAuthFileAtomically(t *testing.T) {
	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master",
		testBranchSpec{name: "master", contents: "remote master branch\n"},
	)
	store := NewGitTokenStore(remoteDir, "", "", "")
	authDir := filepath.Join(root, "workspace", "auths")
	store.SetBaseDir(authDir)
	if errEnsure := store.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository: %v", errEnsure)
	}

	path := filepath.Join(authDir, "atomic.json")
	// A directory at the old fixed temp name makes a write to "<path>.tmp" fail.
	if errMkdir := os.MkdirAll(path+".tmp", 0o700); errMkdir != nil {
		t.Fatalf("create stale temp: %v", errMkdir)
	}

	for i, token := range []string{"first", "second"} {
		auth := &cliproxyauth.Auth{
			ID:       "atomic.json",
			FileName: "atomic.json",
			Provider: "codex",
			Metadata: map[string]any{"type": "codex", "access_token": token},
		}
		if _, errSave := store.Save(context.Background(), auth); errSave != nil {
			t.Fatalf("Save %d: %v", i, errSave)
		}
		info, errStat := os.Stat(path)
		if errStat != nil {
			t.Fatalf("stat auth file: %v", errStat)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("auth file mode = %o, want 600", perm)
		}
		assertRemoteFileContents(t, remoteDir, "master", "auths/atomic.json", `{"access_token":"`+token+`","disabled":false,"type":"codex"}`)
	}

	entries, errRead := os.ReadDir(authDir)
	if errRead != nil {
		t.Fatalf("read auth dir: %v", errRead)
	}
	for _, entry := range entries {
		if name := entry.Name(); name != "atomic.json" && name != "atomic.json.tmp" && !entry.IsDir() {
			t.Fatalf("unexpected leftover file %q in auth dir", name)
		}
	}
}
