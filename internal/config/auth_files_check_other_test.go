//go:build !windows

package config

import "testing"

func TestCheckAuthFilesOwnerOnlyNonWindowsNoOp(t *testing.T) {
	// A missing path must not even be enumerated on non-Windows platforms.
	if err := CheckAuthFilesOwnerOnly("missing-auth-directory", false); err != nil {
		t.Fatalf("non-Windows check is not a no-op: %v", err)
	}
}
