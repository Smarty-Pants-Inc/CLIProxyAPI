package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestCodexRefreshPatchDoesNotRecreateDeletedSource(t *testing.T) {
	for _, directStorage := range []bool{false, true} {
		t.Run(map[bool]string{false: "file_store", true: "token_storage"}[directStorage], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "removed.json")
			before := map[string]any{"type": "codex", "access_token": "old", "refresh_token": "old-refresh"}
			after := map[string]any{"type": "codex", "access_token": "new", "refresh_token": "new-refresh"}
			patch := codex.NewCredentialRefreshPatch(before, after, true, false)
			if err := codex.WriteJSONFileAtomic(path, before); err != nil {
				t.Fatal(err)
			}
			store := NewFileTokenStore()
			store.SetBaseDir(dir)
			if err := store.Delete(context.Background(), path); err != nil {
				t.Fatal(err)
			}
			var errSave error
			if directStorage {
				storage := &codex.CodexTokenStorage{AccessToken: "new", RefreshToken: "new-refresh", RefreshPatch: patch}
				errSave = storage.SaveTokenToFile(path)
			} else {
				_, errSave = store.Save(context.Background(), &cliproxyauth.Auth{ID: "removed.json", Provider: "codex", Metadata: after, CodexRefreshPatch: patch})
			}
			if !errors.Is(errSave, codex.ErrRefreshNotPersisted) {
				t.Errorf("refresh error = %v, want not-persisted", errSave)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("refresh recreated deleted credential: %v", err)
			}
			loaded, err := store.List(context.Background())
			if err != nil || len(loaded) != 0 {
				t.Fatalf("restart loaded deleted credential: count=%d err=%v", len(loaded), err)
			}
		})
	}
}
