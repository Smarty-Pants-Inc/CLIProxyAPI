//go:build !windows

package misc

import (
	"path/filepath"
	"testing"
)

func authFileRenameErrorDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "auth")
}
