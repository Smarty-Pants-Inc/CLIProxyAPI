//go:build unix

package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v6"
)

func TestRecoveryRefusesSymlinkedAuthRoot(t *testing.T) {
	for _, component := range []string{"auths", "parent", "store"} {
		t.Run(component, func(t *testing.T) {
			root := t.TempDir()
			remoteDir := setupGitRemoteRepository(t, root, "master",
				testBranchSpec{name: "master", contents: "remote master branch\n"},
			)
			repoDir := filepath.Join(root, "workspace")
			store := NewGitTokenStore(remoteDir, "", "", "")
			store.SetBaseDir(filepath.Join(repoDir, "auths"))
			if errEnsure := store.EnsureRepository(); errEnsure != nil {
				t.Fatal(errEnsure)
			}
			switch component {
			case "auths":
				if errRename := os.Rename(store.baseDir, filepath.Join(repoDir, "real-auths")); errRename != nil {
					t.Fatal(errRename)
				}
				if errLink := os.Symlink("real-auths", store.baseDir); errLink != nil {
					t.Fatal(errLink)
				}
			case "parent":
				if errLink := os.Symlink(".", filepath.Join(repoDir, "parent")); errLink != nil {
					t.Fatal(errLink)
				}
				store.baseDir = filepath.Join(repoDir, "parent", "auths")
			case "store":
				realRepoDir := filepath.Join(root, "real-workspace")
				if errRename := os.Rename(repoDir, realRepoDir); errRename != nil {
					t.Fatal(errRename)
				}
				if errLink := os.Symlink(realRepoDir, repoDir); errLink != nil {
					t.Fatal(errLink)
				}
			}
			local := filepath.Join(store.baseDir, "local.json")
			writeWithMode(t, local, 0o644)
			gitConfig := filepath.Join(repoDir, ".git", "config")
			configBefore, errRead := os.ReadFile(gitConfig)
			if errRead != nil {
				t.Fatal(errRead)
			}
			errRecover := store.recoverRepositoryLocked(repoDir, nil, nil, nil, nil, (*git.Repository).Close, os.Rename)
			if errRecover == nil || !strings.Contains(errRecover.Error(), "symlink") {
				t.Errorf("recovery error = %v, want symlink refusal", errRecover)
			}
			// Refusal must leave the live worktree and repository untouched,
			// rather than installing credentials with their original loose mode.
			assertMode(t, local, 0o644)
			assertLocalFileContents(t, local, "{}")
			assertLocalFileContents(t, gitConfig, string(configBefore))
			entries, errReadDir := os.ReadDir(root)
			if errReadDir != nil {
				t.Fatal(errReadDir)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".gitstore-recovery-") {
					t.Errorf("recovery wrote temporary directory %s", entry.Name())
				}
			}
		})
	}
}

func TestRecoveryNormalAuthRootResolvedPathsKeepModes(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	mkdirWithMode(t, filepath.Join(source, "auths"), 0o700)
	mkdirWithMode(t, filepath.Join(source, "scripts"), 0o755)
	writeWithMode(t, filepath.Join(source, "auths", "direct.json"), 0o644)
	writeWithMode(t, filepath.Join(source, "auths", "aliased.json"), 0o644)
	writeWithMode(t, filepath.Join(source, "scripts", "run.sh"), 0o755)
	// The auth root is an ordinary directory. A different path to it must
	// still use the auth writer, while non-auth files retain their mode.
	if errLink := os.Symlink("auths", filepath.Join(source, "alias")); errLink != nil {
		t.Fatal(errLink)
	}
	paths := map[string]struct{}{"auths/direct.json": {}, "alias/aliased.json": {}, "scripts/run.sh": {}}
	if errApply := applyRecoveryLocalChanges(source, target, paths, "auths"); errApply != nil {
		t.Fatal(errApply)
	}
	assertMode(t, filepath.Join(target, "auths", "direct.json"), 0o600)
	assertMode(t, filepath.Join(target, "scripts", "run.sh"), 0o755)
	assertMode(t, filepath.Join(target, "alias", "aliased.json"), 0o600)
}

func TestRecoveryDotDotCannotDodgeAuthClassification(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	mkdirWithMode(t, filepath.Join(source, "auths"), 0o700)
	writeWithMode(t, filepath.Join(source, "auths", "local.json"), 0o644)
	paths := map[string]struct{}{"other/../auths/local.json": {}}
	if errApply := applyRecoveryLocalChanges(source, target, paths, "auths"); errApply != nil {
		t.Fatal(errApply)
	}
	assertLocalFileContents(t, filepath.Join(target, "auths", "local.json"), "{}")
	assertMode(t, filepath.Join(target, "auths", "local.json"), 0o600)
}
