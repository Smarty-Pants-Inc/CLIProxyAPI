//go:build windows

package misc

import (
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// RestrictAuthDir applies the shared config policy: a protected current-user-only
// DACL on the resolved auth directory, refusing unsafe ownership.
func RestrictAuthDir(path string) error {
	return config.RestrictAuthDir(path)
}

// RestrictAuthDirForStartup secures and verifies the entire existing auth tree
// without following symlinks or reparse points, before any tokens are loaded.
func RestrictAuthDirForStartup(path string) error {
	return config.RestrictAuthDirForStartup(path)
}

func createPrivateAuthTemp(dir string) (*os.File, error) {
	// The shared helper creates and validates the private DACL before returning
	// the empty file, so token bytes never land in an inherited broad ACL.
	return config.CreatePrivateAuthTemp(dir)
}
