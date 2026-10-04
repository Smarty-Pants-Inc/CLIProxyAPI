//go:build windows

package config

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockConfigFile(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &windows.Overlapped{})
}

func unlockConfigFile(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &windows.Overlapped{})
}

// Windows does not support fsync on directory handles opened by os.Open.
func syncConfigDir(string) error { return nil }
