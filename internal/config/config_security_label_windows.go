//go:build windows

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func secureConfigMAC(staging *os.File, path string, original os.FileInfo) error {
	if original == nil {
		return nil
	}
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	before, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := before.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot inspect original config owner")
	}
	// A writer cannot silently transfer another account's config to itself.
	return verifyConfigOwnerDACL(staging, owner)
}
