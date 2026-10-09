//go:build unix

package store

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEnforceOwnerOnlyEntryUnknownFIFOIsNeverOpened(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "unknown-fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	opened := false
	ownerOnlyWalkBeforeOpen = func(_, _ string) { opened = true }
	t.Cleanup(func() { ownerOnlyWalkBeforeOpen = nil })
	// Bypass ReadDir's known FIFO hint: false is exactly the hintDir value
	// passed by the walk for an unknown DirEntry.Type()==0.
	if err := enforceOwnerOnlyEntry(int(dir.Fd()), root, "unknown-fifo", false); err != nil {
		t.Fatal(err)
	}
	if opened {
		t.Fatal("unknown-type FIFO reached the open hook")
	}
}

func TestEnforceOwnerOnlyEntryRejectsSwapAfterStat(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		originalDir, nextDir bool
	}{
		{"regular_to_regular", false, false},
		{"regular_to_directory", false, true},
		{"directory_to_directory", true, true},
		{"directory_to_regular", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			entry := filepath.Join(root, "entry")
			if tc.originalDir {
				mkdirWithMode(t, entry, 0o755)
			} else {
				writeWithMode(t, entry, 0o644)
			}
			dir, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dir.Close() }()
			swapped := false
			ownerOnlyWalkBeforeOpen = func(dirPath, name string) {
				if dirPath != root || name != "entry" {
					t.Fatal("unexpected open hook target")
				}
				// Keep the original inode alive so the replacement cannot reuse it.
				if err := os.Rename(entry, filepath.Join(root, "original")); err != nil {
					t.Fatal(err)
				}
				if tc.nextDir {
					mkdirWithMode(t, entry, 0o755)
					writeWithMode(t, filepath.Join(entry, "untouched.json"), 0o644)
				} else {
					writeWithMode(t, entry, 0o644)
				}
				swapped = true
			}
			t.Cleanup(func() { ownerOnlyWalkBeforeOpen = nil })
			if err := enforceOwnerOnlyEntry(int(dir.Fd()), root, "entry", tc.originalDir); err != nil {
				t.Fatal(err)
			}
			if !swapped {
				t.Fatal("swap hook did not run")
			}
			if tc.nextDir {
				assertMode(t, entry, 0o755)
				assertMode(t, filepath.Join(entry, "untouched.json"), 0o644)
			} else {
				assertMode(t, entry, 0o644)
			}
		})
	}
}
