package misc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteAuthFileAtomicReplacesFileWithMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.json")
	if errWrite := os.WriteFile(path, []byte(`{"old":true}`), 0o644); errWrite != nil {
		t.Fatalf("seed: %v", errWrite)
	}
	if errWrite := WriteAuthFileAtomic(path, []byte(`{"new":true}`)); errWrite != nil {
		t.Fatalf("WriteAuthFileAtomic: %v", errWrite)
	}
	got, errRead := os.ReadFile(path)
	if errRead != nil || string(got) != `{"new":true}` {
		t.Fatalf("content = %q, %v", got, errRead)
	}
	info, errStat := os.Stat(path)
	if errStat != nil {
		t.Fatalf("stat: %v", errStat)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("leftover temp files: %d entries", len(entries))
	}
}

func TestWriteAuthFileAtomicReplacesSymlinkNotTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on windows")
	}
	dir := t.TempDir()
	other := t.TempDir()
	target := filepath.Join(other, "target.json")
	if errWrite := os.WriteFile(target, []byte(`{"target":true}`), 0o600); errWrite != nil {
		t.Fatalf("seed target: %v", errWrite)
	}
	link := filepath.Join(dir, "auth.json")
	if errLink := os.Symlink(target, link); errLink != nil {
		t.Fatalf("symlink: %v", errLink)
	}
	if errWrite := WriteAuthFileAtomic(link, []byte(`{"new":true}`)); errWrite != nil {
		t.Fatalf("WriteAuthFileAtomic: %v", errWrite)
	}
	info, errLstat := os.Lstat(link)
	if errLstat != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("auth path should now be a regular file: %v %v", info, errLstat)
	}
	if got, _ := os.ReadFile(target); string(got) != `{"target":true}` {
		t.Fatalf("symlink target was written through: %q", got)
	}
}

func TestWriteAuthFileAtomicMissingDirLeavesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "auth.json")
	if errWrite := WriteAuthFileAtomic(path, []byte(`{}`)); errWrite == nil {
		t.Fatal("expected error for missing directory")
	}
	if _, errStat := os.Stat(path); !os.IsNotExist(errStat) {
		t.Fatalf("auth file should not exist: %v", errStat)
	}
}

func TestWriteAuthFileAtomicRemovesTempOnRenameError(t *testing.T) {
	dir := t.TempDir()
	// Renaming a file over a non-empty directory fails, which exercises cleanup.
	path := filepath.Join(dir, "auth.json")
	if errMkdir := os.MkdirAll(filepath.Join(path, "child"), 0o700); errMkdir != nil {
		t.Fatalf("mkdir: %v", errMkdir)
	}
	if errWrite := WriteAuthFileAtomic(path, []byte(`{}`)); errWrite == nil {
		t.Fatal("expected rename error")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "auth.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("temp file left behind: %v", names)
	}
}

// A valid auth name at the 255-byte component limit must still be writable: the temp
// name may not grow with the target name (CLIProxyAPI#81 review P2).
func TestWriteAuthFileAtomicAcceptsMaxLengthName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, strings.Repeat("a", 250)+".json")
	if errWrite := os.WriteFile(path, []byte(`{"old":true}`), 0o600); errWrite != nil {
		t.Skipf("filesystem refuses a 255-byte name: %v", errWrite)
	}
	if errWrite := WriteAuthFileAtomic(path, []byte(`{"new":true}`)); errWrite != nil {
		t.Fatalf("WriteAuthFileAtomic: %v", errWrite)
	}
	got, errRead := os.ReadFile(path)
	if errRead != nil || string(got) != `{"new":true}` {
		t.Fatalf("content = %q, %v", got, errRead)
	}
}
