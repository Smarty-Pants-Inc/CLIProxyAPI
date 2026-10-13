//go:build windows

package misc

import (
	"os"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// RestrictAuthDir applies the shared config policy: a protected current-user-only
// DACL with owner-full OI/CI inheritance on the resolved auth directory, refusing
// unsafe ownership and preserving owner access to existing inherited-only files.
func RestrictAuthDir(path string) error {
	return config.RestrictAuthDir(path)
}

func createPrivateAuthTemp(dir string) (*os.File, error) {
	// The shared helper creates and validates the private DACL before returning
	// the empty file, so token bytes never land in an inherited broad ACL.
	return config.CreatePrivateAuthTemp(dir)
}
