//go:build windows

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Numeric Unix modes cannot protect Windows files. Create lock and staging
// handles with a protected owner-only DACL before writing any secret bytes.
func privateConfigSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
}

func openPrivateConfigFile(path string, disposition uint32) (*os.File, error) {
	sd, err := privateConfigSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	// No FILE_SHARE_DELETE: an open stable lock cannot be replaced underneath
	// another cooperating publisher. Existing locks must already have our owner.
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE | windows.WRITE_DAC)
	if disposition == windows.CREATE_NEW {
		// A refused, newly allocated stage is removed through its own handle,
		// never by a pathname that could have been replaced after closing it.
		access |= windows.DELETE
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	return securePrivateConfigFile(os.NewFile(uintptr(handle), path), disposition, sd)
}

func securePrivateConfigFile(file *os.File, disposition uint32, sd *windows.SECURITY_DESCRIPTOR) (*os.File, error) {
	handle := windows.Handle(file.Fd())
	if err := restrictPrivateConfigHandle(handle, sd); err != nil {
		if disposition == windows.CREATE_NEW {
			deleteFile := byte(1)
			if errDelete := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1); errDelete != nil {
				err = fmt.Errorf("%w (remove refused staging file: %v)", err, errDelete)
			}
		}
		if errClose := file.Close(); errClose != nil {
			return nil, fmt.Errorf("secure config file: %w (close: %v)", err, errClose)
		}
		return nil, fmt.Errorf("secure config file: %w", err)
	}
	return file, nil
}

// restrictPrivateConfigHandle is shared by config files and auth directories.
// Never repair an incompatible owner, even if its DACL matches.
func restrictPrivateConfigHandle(handle windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
	actual, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil && !hasPrivateConfigOwner(actual, sd) {
		err = fmt.Errorf("config file owner is not the current user")
	}
	var dacl *windows.ACL
	if err == nil {
		dacl, _, err = sd.DACL()
	}
	if err == nil {
		err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	if err == nil {
		actual, err = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err == nil && !hasPrivateConfigDACL(actual, sd) {
			err = fmt.Errorf("current-user owner and protected private config DACL were not established")
		}
	}
	runtime.KeepAlive(sd)
	return err
}

// hasPrivateConfigDACL validates the actual access policy, not the whole SDDL
// representation. GetSecurityInfo can return auto-inheritance bookkeeping that
// differs from the input template. The owner must still match the current user;
// group and auto-inheritance bookkeeping are not additional DACL grants.
func hasPrivateConfigDACL(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	if actual == nil || expected == nil || !actual.IsValid() || !expected.IsValid() {
		return false
	}
	if !hasPrivateConfigOwner(actual, expected) {
		return false
	}
	control, _, err := actual.Control()
	if err != nil {
		return false
	}
	dacl, _, err := actual.DACL()
	if err != nil || dacl == nil {
		return false
	}
	// Build a descriptor containing only the unchanged DACL and the protection
	// flag. This strips descriptor metadata, never ACEs or ACE inheritance flags.
	projection, err := windows.NewSecurityDescriptor()
	if err != nil {
		return false
	}
	if err = projection.SetDACL(dacl, true, false); err != nil {
		return false
	}
	if err = projection.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return false
	}
	expectedDACL, _, err := expected.DACL()
	if err != nil || expectedDACL == nil {
		return false
	}
	expectedProjection, err := windows.NewSecurityDescriptor()
	if err != nil {
		return false
	}
	if err = expectedProjection.SetDACL(expectedDACL, true, false); err != nil {
		return false
	}
	if err = expectedProjection.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return false
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil {
		return false
	}
	expectedOwner, _, err := expected.Owner()
	if err != nil || expectedOwner == nil {
		return false
	}
	matches := privateConfigOwnerAndDACLMatches(uint16(control), true, owner.String(), expectedOwner.String(), projection.String(), expectedProjection.String())
	runtime.KeepAlive(actual)
	return matches
}

// Missing ownership or an API error is a refusal, not harmless metadata.
func hasPrivateConfigOwner(actual, expected *windows.SECURITY_DESCRIPTOR) bool {
	if actual == nil || expected == nil || !actual.IsValid() || !expected.IsValid() {
		return false
	}
	owner, _, err := actual.Owner()
	if err != nil || owner == nil {
		return false
	}
	user, _, err := expected.Owner()
	return err == nil && user != nil && owner.Equals(user)
}

func openConfigPublicationLock(path string) (*os.File, error) {
	return openPrivateConfigFile(path, windows.OPEN_ALWAYS)
}

func createConfigPublicationStage(dir string) (*os.File, error) {
	return createPrivateConfigTemp(dir, "config")
}

func createPrivateConfigTemp(dir, prefix string) (*os.File, error) {
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		file, err := openPrivateConfigFile(filepath.Join(dir, "."+prefix+"-"+hex.EncodeToString(random[:])+".tmp"), windows.CREATE_NEW)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		return file, err
	}
	return nil, fmt.Errorf("unable to allocate private %s staging file", prefix)
}

func lockConfigPublication(file *os.File) error {
	return windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, new(windows.Overlapped))
}

func unlockConfigPublication(file *os.File) error {
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped))
}

func replaceConfigPublication(source, destination string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// Staging is on the same volume. Never allow COPY_ALLOWED or truncation.
	// WRITE_THROUGH makes the native replacement complete before returning.
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// Windows directory handles do not support Unix fsync. Durability is supplied
// by the staged file's Sync and write-through native replacement above.
func syncConfigPublicationDir(string) error { return nil }
