package logging

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Keep: data safety for raw request bodies, including existing deployment files.
func TestRequestLogOwnerOnlyPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "logs")
	oldSpool := filepath.Join(dir, "request-log-parts-old")
	if err := os.MkdirAll(oldSpool, 0755); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(dir, "old.log")
	oldPart := filepath.Join(oldSpool, "old.tmp")
	for _, p := range []string{oldFile, oldPart} {
		if err := os.WriteFile(p, []byte("synthetic"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0755); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outside, "outside.log")
	if err := os.WriteFile(outsideFile, []byte("synthetic"), 0644); err != nil {
		t.Fatal(err)
	}
	// Explicit modes keep this test independent of the process umask.
	for _, p := range []string{dir, oldSpool, outside} {
		if err := os.Chmod(p, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{oldFile, oldPart, outsideFile} {
		if err := os.Chmod(p, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(dir, "linked.log")); err != nil {
		t.Fatal(err)
	}
	logger := NewFileRequestLogger(true, dir, "", 10)
	mode := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
	}
	mode(dir, 0700)
	mode(oldSpool, 0700)
	mode(oldFile, 0600)
	mode(oldPart, 0600)
	mode(outside, 0755)
	mode(outsideFile, 0644)
	for i := 0; i < 2; i++ {
		f, path, err := createUniqueLogFile(dir, "collision.log")
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		mode(path, 0600)
	}
	source, err := logger.NewFileBodySource("permissions")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Cleanup() }()
	part, err := source.CreatePart("part")
	if err != nil {
		t.Fatal(err)
	}
	mode(source.dir, 0700)
	mode(part.Name(), 0600)
	if err := part.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(part.Name()); err != nil {
		t.Fatal(err)
	}
	if err := source.AppendBytes([]byte("synthetic recreated part")); err != nil {
		t.Fatal(err)
	}
	mode(part.Name(), 0600)
	writer, err := logger.LogStreamingRequest("/v1/responses", "POST", nil, []byte("synthetic"), "12345678")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"request-body-*.tmp", "response-body-*.tmp"} {
		paths, err := filepath.Glob(filepath.Join(dir, name))
		if err != nil || len(paths) != 1 {
			t.Fatalf("temp files %s = %v, %v", name, paths, err)
		}
		mode(paths[0], 0600)
	}
	writer.WriteChunkAsync([]byte("data: synthetic\n\n"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*12345678.log"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("stream logs = %v, %v", paths, err)
	}
	mode(paths[0], 0600)
}
