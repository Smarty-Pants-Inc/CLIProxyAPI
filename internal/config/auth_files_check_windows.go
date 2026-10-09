//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CheckAuthFilesOwnerOnly inspects top-level auth files without reading their
// contents or changing their ACLs. Subdirectories are out of scope, but every
// reparse-point entry is refused without following it.
func CheckAuthFilesOwnerOnly(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("check auth files: resolve current user: %w", err)
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return fmt.Errorf("check auth files: resolve current-user account name: %w", err)
	}
	if domain != "" {
		account = domain + `\` + account
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("check auth files in %q: %w", dir, err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		name, errName := windows.UTF16PtrFromString(path)
		if errName != nil {
			return authFileCheckError(path, account, errName)
		}
		attributes, errAttributes := windows.GetFileAttributes(name)
		if errAttributes != nil {
			return authFileCheckError(path, account, errAttributes)
		}
		// Check before skipping directories: junctions and directory symlinks
		// are also reparse points, not subdirectories we may safely ignore.
		if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return authFileCheckError(path, account, fmt.Errorf("reparse point refused; replace this entry with a regular file before fixing its ACL"))
		}
		if attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || !entry.Type().IsRegular() {
			continue
		}
		if errCheck := checkAuthFileDACL(name, user.User.Sid); errCheck != nil {
			return authFileCheckError(path, account, errCheck)
		}
	}
	return nil
}

func authFileCheckError(path, account string, cause error) error {
	// /grant:r alone does not remove explicit grants to other trustees. Reset
	// to the already-protected parent policy first, then make it explicit.
	return fmt.Errorf("refusing auth file %q: %w (fix it with: icacls \"%s\" /reset && icacls \"%s\" /inheritance:r /grant:r \"%s:F\")", path, cause, path, path, account)
}

func checkAuthFileDACL(name *uint16, user *windows.SID) (err error) {
	// READ_CONTROL only: no content reads or write access. OPEN_REPARSE_POINT
	// binds inspection to the entry itself even if it changed after enumeration.
	// Without delete sharing the opened entry cannot be replaced during inspection.
	handle, err := windows.CreateFile(name, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return fmt.Errorf("open for DACL inspection: %w", err)
	}
	defer func() {
		if errClose := windows.CloseHandle(handle); errClose != nil {
			if err != nil {
				err = fmt.Errorf("%w (close auth file: %v)", err, errClose)
			} else {
				err = fmt.Errorf("close auth file: %w", errClose)
			}
		}
	}()
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect auth file: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("reparse point refused; replace this entry with a regular file before fixing its ACL")
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return nil
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read auth file DACL: %w", err)
	}
	return authFileDACLIsOwnerOnly(sd, user)
}

func authFileDACLIsOwnerOnly(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if sd == nil || !sd.IsValid() {
		return fmt.Errorf("missing or invalid security descriptor")
	}
	defer runtime.KeepAlive(sd)
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read auth file DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("null DACL permits access to everyone")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err = windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read auth file ACE %d: %w", i, err)
		}
		// Ordinary allow and deny ACEs have the same trustee layout. Do not
		// calculate effective access: a deny never excuses another user's grant.
		// Fail closed for unfamiliar ACE layouts rather than misreading a SID.
		if ace == nil || (ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) {
			return fmt.Errorf("unsupported auth file ACE %d", i)
		}
		const minSIDSize = 8
		sidOffset := unsafe.Offsetof(ace.SidStart)
		if uintptr(ace.Header.AceSize) < sidOffset+minSIDSize {
			return fmt.Errorf("invalid auth file ACE %d", i)
		}
		trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustee.IsValid() || uintptr(trustee.Len()) > uintptr(ace.Header.AceSize)-sidOffset {
			return fmt.Errorf("invalid auth file trustee in ACE %d", i)
		}
		if !trustee.Equals(user) {
			return fmt.Errorf("ACE %d grants or denies access to a trustee other than the current user (%s)", i, trustee.String())
		}
	}
	return nil
}
