//go:build !linux

package config

import "os"

func openConfigFileLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}

// Native config security support remains enforced by the replacement helper.
func secureConfigLockIdentity(*os.File, os.FileInfo) error { return nil }
