//go:build windows

package auth

import "os"

// fileOwnerUID cannot prove a POSIX owner on Windows, so a legacy affinity
// state file is never trusted there (it is ignored; requests degrade).
func fileOwnerUID(os.FileInfo) (int, bool) { return 0, false }
