//go:build linux

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxOwnerOnlyWalkNeverDataOpensFIFO(t *testing.T) {
	for _, kind := range []string{"fifo", "regular_swap", "directory_swap"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			entry := filepath.Join(root, "entry")
			watchFD, errWatch := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
			if errWatch != nil {
				t.Fatal(errWatch)
			}
			defer func() { _ = unix.Close(watchFD) }()
			makeFIFO := func() {
				if errFIFO := unix.Mkfifo(entry, 0o644); errFIFO != nil {
					t.Fatal(errFIFO)
				}
				if errChmod := os.Chmod(entry, 0o644); errChmod != nil {
					t.Fatal(errChmod)
				}
				// O_PATH does not emit IN_OPEN; even a nonblocking data open
				// of this FIFO does. Events are queued synchronously on open,
				// so checking after the walk needs no timer or writer process.
				if _, errAdd := unix.InotifyAddWatch(watchFD, entry, unix.IN_OPEN); errAdd != nil {
					t.Fatal(errAdd)
				}
			}
			swapped := false
			if kind == "fifo" {
				makeFIFO()
			} else {
				if kind == "directory_swap" {
					mkdirWithMode(t, entry, 0o755)
				} else {
					writeWithMode(t, entry, 0o644)
				}
				ownerOnlyWalkBeforeOpen = func(dirPath, name string) {
					if dirPath != root || name != "entry" {
						t.Fatalf("unexpected swap target %s/%s", dirPath, name)
					}
					if errRename := os.Rename(entry, filepath.Join(root, "original")); errRename != nil {
						t.Fatal(errRename)
					}
					makeFIFO()
					swapped = true
				}
				t.Cleanup(func() { ownerOnlyWalkBeforeOpen = nil })
			}
			// There is no FIFO writer. The walk must complete without a
			// blocking open, and must not issue even a nonblocking data open.
			if errEnforce := enforceOwnerOnlyTree(root); errEnforce != nil {
				t.Fatal(errEnforce)
			}
			if kind != "fifo" && !swapped {
				t.Fatal("swap hook did not run")
			}
			assertMode(t, entry, 0o644)
			var events [unix.SizeofInotifyEvent * 4]byte
			n, errRead := unix.Read(watchFD, events[:])
			if !errors.Is(errRead, unix.EAGAIN) {
				t.Fatalf("FIFO was data-opened: inotify read = %d, %v; want EAGAIN (no IN_OPEN)", n, errRead)
			}
		})
	}
}
