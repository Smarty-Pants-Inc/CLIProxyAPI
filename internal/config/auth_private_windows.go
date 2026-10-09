//go:build windows

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// ERROR_UNTRUSTED_MOUNT_POINT from the Windows SDK's winerror.h is not yet
// provided by x/sys/windows.
const errorUntrustedMountPoint syscall.Errno = 448

// RestrictAuthDir establishes a protected, current-user-only DACL on an existing
// auth directory. Trusted configured directory symlinks are followed, but all
// security checks and changes apply to the pinned target handle. Windows may
// reject a non-admin-created symlink as an untrusted mount point; that refusal
// is preserved without bypassing redirection trust or changing the target.
// Foreign owners and non-directories are refused; ownership is never repaired.
func RestrictAuthDir(path string) (err error) {
	sd, err := privateConfigSecurityDescriptor()
	if err != nil {
		return fmt.Errorf("secure auth directory: %w", err)
	}
	name, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("secure auth directory: %w", err)
	}
	// Keep all checks and ACL changes bound to one handle, without delete sharing.
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		if errors.Is(err, errorUntrustedMountPoint) {
			return fmt.Errorf("open auth directory: refusing untrusted mount point: %w", err)
		}
		return fmt.Errorf("open auth directory: %w", err)
	}
	defer func() {
		if errClose := windows.CloseHandle(handle); errClose != nil {
			if err != nil {
				err = fmt.Errorf("%w (close auth directory: %v)", err, errClose)
			} else {
				err = fmt.Errorf("close auth directory: %w", errClose)
			}
		}
	}()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect auth directory: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("auth path is not a directory")
	}
	if err = restrictPrivateConfigHandle(handle, sd); err != nil {
		return fmt.Errorf("secure auth directory: %w", err)
	}
	return nil
}

// CreatePrivateAuthTemp creates an empty, exclusively allocated auth staging
// file. Its current-user owner and protected exact DACL are validated before the
// caller can write token bytes. The caller closes and removes the returned file.
func CreatePrivateAuthTemp(dir string) (*os.File, error) {
	return createPrivateConfigTemp(dir, "auth")
}
