//go:build unix

package store

import (
	"os"
	"path/filepath"
	"testing"
)

// CLIProxyAPI#111 final round: the owner-only walk opens every entry relative
// to its parent directory descriptor with O_NOFOLLOW and changes modes only
// through the opened descriptor, so no symlink, present from the start or
// swapped in during the walk, can redirect a chmod outside the tree.

func writeWithMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if errWrite := os.WriteFile(path, []byte("{}"), mode); errWrite != nil {
		t.Fatal(errWrite)
	}
	if errChmod := os.Chmod(path, mode); errChmod != nil {
		t.Fatal(errChmod)
	}
}

func mkdirWithMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if errMkdir := os.MkdirAll(path, mode); errMkdir != nil {
		t.Fatal(errMkdir)
	}
	if errChmod := os.Chmod(path, mode); errChmod != nil {
		t.Fatal(errChmod)
	}
}

func TestEnforceOwnerOnlyTreeRestrictsNestedTreeAndSkipsSymlinks(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "auths")
	nested := filepath.Join(root, "team", "deeper")
	mkdirWithMode(t, root, 0o755)
	mkdirWithMode(t, filepath.Join(root, "team"), 0o755)
	mkdirWithMode(t, nested, 0o755)
	writeWithMode(t, filepath.Join(root, "a.json"), 0o644)
	writeWithMode(t, filepath.Join(root, "team", "b.json"), 0o644)
	writeWithMode(t, filepath.Join(nested, "c.json"), 0o666)

	outsideFile := filepath.Join(base, "outside.json")
	writeWithMode(t, outsideFile, 0o644)
	outsideDir := filepath.Join(base, "outside-dir")
	mkdirWithMode(t, outsideDir, 0o755)
	outsideInner := filepath.Join(outsideDir, "inner.json")
	writeWithMode(t, outsideInner, 0o644)
	if errLink := os.Symlink(outsideFile, filepath.Join(root, "link.json")); errLink != nil {
		t.Fatal(errLink)
	}
	if errLink := os.Symlink(outsideDir, filepath.Join(nested, "linkdir")); errLink != nil {
		t.Fatal(errLink)
	}

	if errEnforce := enforceOwnerOnlyTree(root); errEnforce != nil {
		t.Fatalf("enforceOwnerOnlyTree: %v", errEnforce)
	}
	assertMode(t, root, 0o700)
	assertMode(t, filepath.Join(root, "team"), 0o700)
	assertMode(t, nested, 0o700)
	assertMode(t, filepath.Join(root, "a.json"), 0o600)
	assertMode(t, filepath.Join(root, "team", "b.json"), 0o600)
	assertMode(t, filepath.Join(nested, "c.json"), 0o600)
	assertMode(t, outsideFile, 0o644)
	assertMode(t, outsideDir, 0o755)
	assertMode(t, outsideInner, 0o644)
	for _, link := range []string{filepath.Join(root, "link.json"), filepath.Join(nested, "linkdir")} {
		if info, errStat := os.Lstat(link); errStat != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s = %v, %v; want an untouched symlink", link, info, errStat)
		}
	}
}

func TestEnforceOwnerOnlyTreeLeavesSymlinkedRootAlone(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	mkdirWithMode(t, target, 0o755)
	writeWithMode(t, filepath.Join(target, "a.json"), 0o644)
	root := filepath.Join(base, "auths")
	if errLink := os.Symlink(target, root); errLink != nil {
		t.Fatal(errLink)
	}
	if errEnforce := enforceOwnerOnlyTree(root); errEnforce != nil {
		t.Fatalf("enforceOwnerOnlyTree: %v", errEnforce)
	}
	assertMode(t, target, 0o755)
	assertMode(t, filepath.Join(target, "a.json"), 0o644)
}

// An entry listed as a regular file or directory is replaced by a symlink to
// an outside target after the listing and before it is opened; the walk must
// not follow it.
func TestEnforceOwnerOnlyTreeDoesNotFollowSymlinkSwappedDuringWalk(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "auths")
	mkdirWithMode(t, root, 0o755)
	writeWithMode(t, filepath.Join(root, "swapped.json"), 0o644)
	mkdirWithMode(t, filepath.Join(root, "swapped-dir"), 0o755)
	writeWithMode(t, filepath.Join(root, "kept.json"), 0o644)

	outsideFile := filepath.Join(base, "outside.json")
	writeWithMode(t, outsideFile, 0o644)
	outsideDir := filepath.Join(base, "outside-dir")
	mkdirWithMode(t, outsideDir, 0o755)
	outsideInner := filepath.Join(outsideDir, "inner.json")
	writeWithMode(t, outsideInner, 0o644)

	swaps := map[string]string{"swapped.json": outsideFile, "swapped-dir": outsideDir}
	swapped := make(map[string]bool)
	ownerOnlyWalkBeforeOpen = func(dirPath, name string) {
		target, ok := swaps[name]
		if !ok || dirPath != root {
			return
		}
		entry := filepath.Join(dirPath, name)
		if errRemove := os.RemoveAll(entry); errRemove != nil {
			t.Error(errRemove)
			return
		}
		if errLink := os.Symlink(target, entry); errLink != nil {
			t.Error(errLink)
			return
		}
		swapped[name] = true
	}
	t.Cleanup(func() { ownerOnlyWalkBeforeOpen = nil })

	if errEnforce := enforceOwnerOnlyTree(root); errEnforce != nil {
		t.Fatalf("enforceOwnerOnlyTree: %v", errEnforce)
	}
	if !swapped["swapped.json"] || !swapped["swapped-dir"] {
		t.Fatalf("swap hook did not run for every entry: %v", swapped)
	}
	assertMode(t, outsideFile, 0o644)
	assertMode(t, outsideDir, 0o755)
	assertMode(t, outsideInner, 0o644)
	assertMode(t, root, 0o700)
	assertMode(t, filepath.Join(root, "kept.json"), 0o600)
}

// Recovery preserves a dirty non-auth file with its own mode (an executable
// script stays executable); only the auth tree is written owner-only.
func TestApplyRecoveryLocalChangesKeepsNonAuthFileMode(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	mkdirWithMode(t, filepath.Join(source, "auths"), 0o700)
	mkdirWithMode(t, filepath.Join(source, "scripts"), 0o755)
	writeWithMode(t, filepath.Join(source, "scripts", "run.sh"), 0o755)
	writeWithMode(t, filepath.Join(source, "auths", "local.json"), 0o644)
	paths := map[string]struct{}{"scripts/run.sh": {}, "auths/local.json": {}}
	if errApply := applyRecoveryLocalChanges(source, target, paths, "auths"); errApply != nil {
		t.Fatalf("applyRecoveryLocalChanges: %v", errApply)
	}
	assertMode(t, filepath.Join(target, "scripts", "run.sh"), 0o755)
	assertMode(t, filepath.Join(target, "auths", "local.json"), 0o600)
}
