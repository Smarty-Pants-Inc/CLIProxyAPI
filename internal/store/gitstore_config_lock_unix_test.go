//go:build !windows

package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A management/SDK/operator publication holds the shared config lock between its
// CAS check and its rename. A git pull that rewrites config.yaml inside that window
// is lost when the rename lands, so the git worktree update must wait for the lock.
func TestGitStoreSyncWaitsForSharedConfigLock(t *testing.T) {
	root := t.TempDir()
	remoteDir := setupGitRemoteRepository(t, root, "master",
		testBranchSpec{name: "master", contents: "remote master branch\n"},
	)
	storeA := NewGitTokenStore(remoteDir, "", "", "")
	storeA.SetBaseDir(filepath.Join(root, "workspace-a", "auths"))
	if errEnsure := storeA.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository A: %v", errEnsure)
	}
	if errWrite := os.WriteFile(storeA.ConfigPath(), []byte("source: original\n"), 0o600); errWrite != nil {
		t.Fatalf("write config A: %v", errWrite)
	}
	if errPersist := storeA.PersistConfig(context.Background()); errPersist != nil {
		t.Fatalf("PersistConfig A: %v", errPersist)
	}
	storeB := NewGitTokenStore(remoteDir, "", "", "")
	storeB.SetBaseDir(filepath.Join(root, "workspace-b", "auths"))
	if errEnsure := storeB.EnsureRepository(); errEnsure != nil {
		t.Fatalf("EnsureRepository B: %v", errEnsure)
	}
	if errWrite := os.WriteFile(storeB.ConfigPath(), []byte("source: remote-modified\n"), 0o600); errWrite != nil {
		t.Fatalf("write config B: %v", errWrite)
	}
	if errPersist := storeB.PersistConfig(context.Background()); errPersist != nil {
		t.Fatalf("PersistConfig B: %v", errPersist)
	}

	configPath, errResolve := filepath.EvalSymlinks(storeA.ConfigPath())
	if errResolve != nil {
		t.Fatalf("resolve config path: %v", errResolve)
	}
	lockFile, errLock := os.OpenFile(configPath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if errLock != nil {
		t.Fatalf("open shared config lock: %v", errLock)
	}
	defer func() { _ = lockFile.Close() }()
	if errFlock := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX); errFlock != nil {
		t.Fatalf("hold shared config lock: %v", errFlock)
	}

	done := make(chan error, 1)
	go func() { done <- storeA.EnsureRepository() }()

	// ponytail: a bounded negative wait. With the fix the sync blocks until the
	// lock is released, so this never flakes GREEN; it can only weaken the RED.
	select {
	case errEnsure := <-done:
		got, _ := os.ReadFile(configPath)
		t.Fatalf("git sync ran while the shared config lock was held (err %v); config.yaml = %q", errEnsure, got)
	case <-time.After(time.Second):
	}
	assertLocalFileContents(t, configPath, "source: original\n")

	if errUnlock := unix.Flock(int(lockFile.Fd()), unix.LOCK_UN); errUnlock != nil {
		t.Fatalf("release shared config lock: %v", errUnlock)
	}
	select {
	case errEnsure := <-done:
		if errEnsure != nil {
			t.Fatalf("EnsureRepository A after lock release: %v", errEnsure)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("EnsureRepository A did not finish after the lock was released")
	}
	assertLocalFileContents(t, configPath, "source: remote-modified\n")
}
