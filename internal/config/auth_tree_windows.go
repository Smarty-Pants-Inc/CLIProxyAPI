//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// RestrictAuthDirForStartup migrates every existing file and subdirectory to the
// protected current-user-only policy before any auth loader runs. Unlike the
// single-directory writer helper, the walk refuses all reparse points (including
// the root), rather than following links or junctions to another tree. Every
// directory remains pinned without write/delete sharing while its children are
// secured. No file contents are read during migration. Any refusal is fatal and
// names the entry; ownership is never repaired.
func RestrictAuthDirForStartup(path string) error {
	root, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("secure auth tree %q: %w", path, err)
	}
	sd, err := privateConfigSecurityDescriptor()
	if err != nil {
		return fmt.Errorf("secure auth tree %q: %w", root, err)
	}
	return restrictAuthTreeEntry(root, true, sd)
}

// restrictAuthEntry uses the shared handle-bound owner check, protected DACL
// setter and read-back verifier. Tests replace it to simulate a refused or
// ineffective ACL change; the walk also independently verifies the result.
var restrictAuthEntry = restrictPrivateConfigHandle

func restrictAuthTreeEntry(path string, requireDir bool, sd *windows.SECURITY_DESCRIPTOR) (err error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("secure auth entry %q: %w", path, err)
	}
	// Request only ACL rights initially: inherited grants may have disappeared
	// when the parent was protected. The owner's implicit ACL rights still let
	// us secure the child before requesting directory enumeration access.
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open auth entry %q: %w", path, err)
	}
	defer func() {
		if errClose := windows.CloseHandle(handle); errClose != nil {
			err = joinAuthTreeCloseError(err, path, errClose)
		}
	}()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect auth entry %q: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("secure auth entry %q: refusing symlink or reparse point", path)
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if requireDir && !isDir {
		return fmt.Errorf("secure auth entry %q: auth path is not a directory", path)
	}
	if err = restrictAuthEntry(handle, sd); err != nil {
		return fmt.Errorf("secure auth entry %q: %w", path, err)
	}
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("verify auth entry %q: %w", path, err)
	}
	if !hasPrivateConfigDACL(actual, sd) {
		return fmt.Errorf("verify auth entry %q: current-user owner and protected owner-only DACL were not established", path)
	}
	if !isDir {
		return nil
	}

	// The secured directory and all walked ancestors are still pinned. Reopen
	// only to acquire enumeration rights, refusing redirection and checking the
	// identity against the ACL handle before enumerating the new handle.
	names, err := readPinnedAuthDir(path, name, info)
	if err != nil {
		return err
	}
	for _, child := range names {
		if err = restrictAuthTreeEntry(filepath.Join(path, child), false, sd); err != nil {
			return err
		}
	}
	return nil
}

func readPinnedAuthDir(path string, name *uint16, pinned windows.ByHandleFileInformation) (names []string, err error) {
	handle, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, fmt.Errorf("enumerate auth directory %q: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer func() {
		if errClose := file.Close(); errClose != nil {
			err = joinAuthTreeCloseError(err, path, errClose)
		}
	}()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, fmt.Errorf("inspect auth directory %q: %w", path, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		info.VolumeSerialNumber != pinned.VolumeSerialNumber ||
		info.FileIndexHigh != pinned.FileIndexHigh || info.FileIndexLow != pinned.FileIndexLow {
		return nil, fmt.Errorf("enumerate auth directory %q: pinned directory identity changed", path)
	}
	names, err = file.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate auth directory %q: %w", path, err)
	}
	return names, nil
}

func joinAuthTreeCloseError(err error, path string, errClose error) error {
	if err != nil {
		return fmt.Errorf("%w (close auth entry %q: %v)", err, path, errClose)
	}
	return fmt.Errorf("close auth entry %q: %w", path, errClose)
}
