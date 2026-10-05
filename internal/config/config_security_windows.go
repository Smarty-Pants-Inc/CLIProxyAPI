//go:build windows

package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configOwnerDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sid := user.User.Sid.String()
	// Protected DACL: exactly one full-access entry, for the owning account.
	return windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
}

func createConfigStaging(dir string) (*os.File, error) {
	sd, err := configOwnerDescriptor()
	if err != nil {
		return nil, fmt.Errorf("private staging descriptor: %w", err)
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err = rand.Read(random[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, ".config-"+hex.EncodeToString(random[:])+".tmp")
		path, errPath := windows.UTF16PtrFromString(name)
		if errPath != nil {
			return nil, errPath
		}
		handle, errCreate := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errCreate == windows.ERROR_FILE_EXISTS || errCreate == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if errCreate != nil {
			return nil, fmt.Errorf("create private config staging: %w", errCreate)
		}
		return os.NewFile(uintptr(handle), name), nil
	}
	return nil, fmt.Errorf("cannot allocate unique config staging file")
}

func secureConfigReplacement(file *os.File, _ os.FileInfo) error {
	expected, err := configOwnerDescriptor()
	if err != nil {
		return err
	}
	owner, _, err := expected.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := expected.DACL()
	if err != nil {
		return err
	}
	if err = windows.SetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("restrict staging DACL: %w", err)
	}
	return verifyConfigOwnerDACL(file, owner)
}

func verifyConfigOwnerDACL(file *os.File, expectedOwner *windows.SID) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(expectedOwner) {
		return fmt.Errorf("config staging owner mismatch")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("config staging DACL is not protected")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf("config staging DACL is not owner-only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err = windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff || !sid.Equals(owner) {
		return fmt.Errorf("config staging DACL grants unexpected access")
	}
	return nil
}

func replaceConfigFile(source, target string) error {
	from, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	absolute, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(absolute)
	if err != nil {
		return err
	}
	name = name[:len(name)-1] // FILE_RENAME_INFO uses a byte length, not a terminator.
	handle, err := windows.CreateFile(from, windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	type renameInfo struct {
		Flags          uint32
		RootDirectory  windows.Handle
		FileNameLength uint32
		FileName       [1]uint16
	}
	var layout renameInfo
	offset := unsafe.Offsetof(layout.FileName)
	buffer := make([]byte, int(offset)+len(name)*2)
	info := (*renameInfo)(unsafe.Pointer(&buffer[0]))
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.FileNameLength = uint32(len(name) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	// A single kernel rename, never a copy/truncate fallback. Windows 10's POSIX
	// replacement keeps existing readers on the old inode. Unsupported filesystems
	// or OS versions refuse publication without changing the original target.
	return windows.SetFileInformationByHandle(handle, windows.FileRenameInfoEx, &buffer[0], uint32(len(buffer)))
}
