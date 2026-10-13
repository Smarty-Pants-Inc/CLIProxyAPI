//go:build !windows

package store

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/go-git/go-git/v6"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// CLIProxyAPI#111 security pass: Git recovery moves a fresh clone into the live
// repository. git checkout writes with permissive modes (0644 files, 0755 dirs
// under umask 022), and preserved local changes kept their own modes; after
// recovery the auth tree must be owner-only again, without following symlinks.

func assertMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	info, errStat := os.Lstat(path)
	if errStat != nil {
		t.Fatalf("stat %s: %v", path, errStat)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}

func TestGitTokenStoreRecoveryRestoresOwnerOnlyModes(t *testing.T) {
	oldMask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(oldMask) })

	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master",
		testBranchSpec{name: "master", contents: "remote master branch\n"},
	)
	owner := NewGitTokenStore(remoteDir, "", "", "")
	owner.SetBaseDir(filepath.Join(root, "owner", "auths"))
	if errEnsure := owner.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository owner: %v", errEnsure)
	}
	if _, errSave := owner.Save(context.Background(), &cliproxyauth.Auth{
		ID: "victim.json", FileName: "victim.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "remote"},
	}); errSave != nil {
		t.Fatalf("save remote auth: %v", errSave)
	}
	nestedDir := filepath.Join(owner.AuthDir(), "team")
	if errMkdir := os.MkdirAll(nestedDir, 0o700); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	nestedPath := filepath.Join(nestedDir, "nested.json")
	if errWrite := os.WriteFile(nestedPath, []byte(`{"type":"codex","access_token":"nested"}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errPersist := owner.PersistAuthFiles(context.Background(), "add nested auth", nestedPath); errPersist != nil {
		t.Fatalf("persist nested auth: %v", errPersist)
	}

	store := NewGitTokenStore(remoteDir, "", "", "")
	repoDir := filepath.Join(root, "workspace")
	authDir := filepath.Join(repoDir, "auths")
	store.SetBaseDir(authDir)
	if errEnsure := store.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository workspace: %v", errEnsure)
	}
	// A preserved local (untracked) auth file with a permissive mode, and a
	// symlink to a file outside the tree whose mode must not change.
	localPath := filepath.Join(authDir, "local.json")
	if errWrite := os.WriteFile(localPath, []byte(`{"type":"codex","access_token":"local"}`), 0o644); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(localPath, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	// A preserved non-auth executable keeps its own mode.
	scriptPath := filepath.Join(repoDir, "run.sh")
	if errWrite := os.WriteFile(scriptPath, []byte("#!/bin/sh\n"), 0o755); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(scriptPath, 0o755); errChmod != nil {
		t.Fatal(errChmod)
	}
	outsidePath := filepath.Join(root, "outside.json")
	if errWrite := os.WriteFile(outsidePath, []byte("{}"), 0o644); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(outsidePath, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	if errLink := os.Symlink(outsidePath, filepath.Join(authDir, "link.json")); errLink != nil {
		t.Fatal(errLink)
	}

	store.dirLock.Lock()
	errRecover := store.recoverRepositoryLocked(repoDir, nil, nil, nil, nil, (*git.Repository).Close, os.Rename)
	store.dirLock.Unlock()
	if errRecover != nil {
		t.Fatalf("recoverRepositoryLocked: %v", errRecover)
	}

	assertMode(t, authDir, 0o700)
	assertMode(t, filepath.Join(authDir, "team"), 0o700)
	assertMode(t, filepath.Join(authDir, "victim.json"), 0o600)
	assertMode(t, filepath.Join(authDir, "team", "nested.json"), 0o600)
	assertMode(t, localPath, 0o600)
	assertMode(t, scriptPath, 0o755)
	assertMode(t, outsidePath, 0o644)
	if info, errStat := os.Lstat(filepath.Join(authDir, "link.json")); errStat != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("preserved symlink = %v, %v; want a symlink", info, errStat)
	}
}

// Every git materialization path, not only recovery, ends owner-only: a pull
// that brings new auth files and directories leaves them 0600/0700.
func TestGitTokenStoreEnsureRepositoryRestoresOwnerOnlyModes(t *testing.T) {
	oldMask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(oldMask) })

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
	nested := filepath.Join(authDir, "team")
	if errMkdir := os.MkdirAll(nested, 0o755); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	loose := filepath.Join(nested, "loose.json")
	if errWrite := os.WriteFile(loose, []byte("{}"), 0o644); errWrite != nil {
		t.Fatal(errWrite)
	}
	for path, mode := range map[string]fs.FileMode{authDir: 0o755, nested: 0o755, loose: 0o644} {
		if errChmod := os.Chmod(path, mode); errChmod != nil {
			t.Fatal(errChmod)
		}
	}
	if errEnsure := store.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository again: %v", errEnsure)
	}
	assertMode(t, authDir, 0o700)
	assertMode(t, nested, 0o700)
	assertMode(t, loose, 0o600)
}

// RECONCILE: a remote auth change applied around a local change rewrites a
// pre-existing 0644 auth file through the atomic writer, ending 0600.
func TestGitTokenStoreReconcileRewritesLooseAuthFileOwnerOnly(t *testing.T) {
	oldMask := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(oldMask) })

	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master",
		testBranchSpec{name: "master", contents: "remote master branch\n"},
	)
	owner := NewGitTokenStore(remoteDir, "", "", "")
	owner.SetBaseDir(filepath.Join(root, "owner", "auths"))
	if errEnsure := owner.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository owner: %v", errEnsure)
	}
	if _, errSave := owner.Save(context.Background(), &cliproxyauth.Auth{
		ID: "modified.json", FileName: "modified.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "old"},
	}); errSave != nil {
		t.Fatalf("Save owner: %v", errSave)
	}
	if errWrite := os.WriteFile(owner.ConfigPath(), []byte("source: original\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errPersist := owner.PersistConfig(context.Background()); errPersist != nil {
		t.Fatalf("PersistConfig owner: %v", errPersist)
	}

	storeA := NewGitTokenStore(remoteDir, "", "", "")
	storeA.SetBaseDir(filepath.Join(root, "workspace-a", "auths"))
	if errEnsure := storeA.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository A: %v", errEnsure)
	}
	// A local config edit makes the pull reconcile instead of fast-forwarding.
	if errWrite := os.WriteFile(storeA.ConfigPath(), []byte("source: local-a\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	loose := filepath.Join(storeA.AuthDir(), "modified.json")
	if errChmod := os.Chmod(loose, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	if _, errSave := owner.Save(context.Background(), &cliproxyauth.Auth{
		ID: "modified.json", FileName: "modified.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "new"},
	}); errSave != nil {
		t.Fatalf("Save remote update: %v", errSave)
	}

	if errEnsure := storeA.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository A reconcile: %v", errEnsure)
	}
	assertLocalFileContents(t, storeA.ConfigPath(), "source: local-a\n")
	assertLocalJSONValue(t, loose, "access_token", "new")
	assertMode(t, loose, 0o600)
}

// The reconcile writer itself (not only the final tightening pass) replaces a
// loose existing file with an owner-only one.
func TestApplyTreePathsReplacesLooseAuthFileOwnerOnly(t *testing.T) {
	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master",
		testBranchSpec{name: "master", contents: "remote master branch\n"},
	)
	store := NewGitTokenStore(remoteDir, "", "", "")
	repoDir := filepath.Join(root, "workspace")
	store.SetBaseDir(filepath.Join(repoDir, "auths"))
	if errEnsure := store.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository: %v", errEnsure)
	}
	if _, errSave := store.Save(context.Background(), &cliproxyauth.Auth{
		ID: "victim.json", FileName: "victim.json", Provider: "codex",
		Metadata: map[string]any{"type": "codex", "access_token": "tree"},
	}); errSave != nil {
		t.Fatalf("Save: %v", errSave)
	}
	repo, errOpen := git.PlainOpen(repoDir)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	defer func() { _ = repo.Close() }()
	head, errHead := repo.Head()
	if errHead != nil {
		t.Fatal(errHead)
	}
	commit, errCommit := repo.CommitObject(head.Hash())
	if errCommit != nil {
		t.Fatal(errCommit)
	}
	tree, errTree := commit.Tree()
	if errTree != nil {
		t.Fatal(errTree)
	}
	victim := filepath.Join(repoDir, "auths", "victim.json")
	if errWrite := os.WriteFile(victim, []byte("stale"), 0o644); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(victim, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	if errApply := applyTreePaths(tree, repoDir, []string{"auths/victim.json"}); errApply != nil {
		t.Fatalf("applyTreePaths: %v", errApply)
	}
	assertLocalJSONValue(t, victim, "access_token", "tree")
	assertMode(t, victim, 0o600)
}

// RECOVER: a preserved local change is copied into the clone through the
// atomic writer and does not keep its old 0644 mode.
func TestApplyRecoveryLocalChangesDoesNotKeepLooseMode(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	if errMkdir := os.MkdirAll(filepath.Join(source, "auths"), 0o700); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	local := filepath.Join(source, "auths", "local.json")
	if errWrite := os.WriteFile(local, []byte(`{"access_token":"local"}`), 0o644); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(local, 0o644); errChmod != nil {
		t.Fatal(errChmod)
	}
	if errApply := applyRecoveryLocalChanges(source, target, map[string]struct{}{"auths/local.json": {}}, "auths"); errApply != nil {
		t.Fatalf("applyRecoveryLocalChanges: %v", errApply)
	}
	recovered := filepath.Join(target, "auths", "local.json")
	assertLocalJSONValue(t, recovered, "access_token", "local")
	assertMode(t, recovered, 0o600)
}
