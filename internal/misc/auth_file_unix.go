//go:build !windows

package misc

import (
	"fmt"
	"os"
)

// RestrictAuthDir is a no-op outside Windows. Callers retain their existing
// POSIX directory mode tightening.
func RestrictAuthDir(path string) error { return nil }

// RestrictAuthDirForStartup is a no-op outside Windows, preserving the existing
// POSIX startup policy and file modes.
func RestrictAuthDirForStartup(path string) error { return nil }

func createPrivateAuthTemp(dir string) (*os.File, error) {
	// ponytail: a short fixed prefix keeps staging names independent of the auth
	// name's length; watchers only react to .json names.
	tmp, err := os.CreateTemp(dir, ".auth-*.tmp")
	if err != nil {
		return nil, err
	}
	// Exact mode on the open handle before any token bytes land.
	if err = tmp.Chmod(authFileMode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return nil, fmt.Errorf("chmod temp auth file: %w", err)
	}
	return tmp, nil
}
