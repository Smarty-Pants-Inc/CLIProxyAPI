//go:build windows

package config

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// The final two SECURITY_INFORMATION bits are documented Win32 process-trust
// label and access-filter classes, not yet named by golang.org/x/sys/windows.
const configSecurityInformation windows.SECURITY_INFORMATION = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.SACL_SECURITY_INFORMATION | windows.LABEL_SECURITY_INFORMATION | windows.ATTRIBUTE_SECURITY_INFORMATION | windows.SCOPE_SECURITY_INFORMATION | 0x00000080 | 0x00000100

// A full SACL query needs ACCESS_SYSTEM_SECURITY on the descriptor itself,
// not merely a privileged process token. Do not enable/acquire privileges here;
// writers unable to inspect the complete boundary must refuse safely.
func openConfigSecuritySource(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL|windows.ACCESS_SYSTEM_SECURITY, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, fmt.Errorf("publication refused: cannot acquire original Windows security inspection rights: %w", err)
	}
	return os.NewFile(uintptr(handle), path), nil
}

func secureConfigMAC(staging *os.File, path string, original os.FileInfo) error {
	if original == nil {
		return nil
	}
	source, err := openConfigSecuritySource(path)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()
	before, err := windows.GetSecurityInfo(windows.Handle(source.Fd()), windows.SE_FILE_OBJECT, configSecurityInformation)
	if err != nil {
		return fmt.Errorf("publication refused: cannot inspect original Windows security descriptor: %w", err)
	}
	owner, _, err := before.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("cannot inspect original config owner")
	}
	// Refuse a descriptor with service readers, inherited ACEs, or security
	// attributes that our private staging descriptor cannot reproduce. Owner-only
	// defaults are safe for new files, not an implicit existing-reader migration.
	if err = verifyOriginalConfigSecurity(source, original, "Windows", func(file *os.File) error {
		if errCheck := verifyConfigOwnerDACL(file, owner); errCheck != nil {
			return errCheck
		}
		// The ordinary staging handle has no ACCESS_SYSTEM_SECURITY right.
		// Reopen only for inspection, then verify this is still its same inode.
		stageSource, errStage := openConfigSecuritySource(staging.Name())
		if errStage != nil {
			return errStage
		}
		defer func() { _ = stageSource.Close() }()
		stageInfo, errStageInfo := staging.Stat()
		if errStageInfo != nil {
			return errStageInfo
		}
		if errIdentity := verifyOriginalConfigSecurity(stageSource, stageInfo, "Windows staging", func(*os.File) error { return nil }); errIdentity != nil {
			return errIdentity
		}
		expected, errExpected := windows.GetSecurityInfo(windows.Handle(stageSource.Fd()), windows.SE_FILE_OBJECT, configSecurityInformation)
		if errExpected != nil {
			return errExpected
		}
		// The complete queried descriptor includes mandatory labels, resource
		// attributes, audit policy, scoped policy, trust labels and access filters. Reject even
		// otherwise owner-only files when those boundaries differ from staging.
		originalPolicy, stagingPolicy := before.String(), expected.String()
		if originalPolicy == "" || stagingPolicy == "" || originalPolicy != stagingPolicy {
			return fmt.Errorf("original descriptor is uninspectable or differs from supported private descriptor")
		}
		return nil
	}); err != nil {
		return err
	}
	return verifyConfigOwnerDACL(staging, owner)
}
