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
	return windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
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
	// another cooperating publisher. Existing locks are secured by handle.
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, disposition, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(sd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	dacl, _, err := sd.DACL()
	if err == nil {
		err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	if err == nil {
		var actual *windows.SECURITY_DESCRIPTOR
		actual, err = windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err == nil && actual.String() != sd.String() {
			err = fmt.Errorf("protected private config DACL was not established")
		}
	}
	runtime.KeepAlive(sd)
	if err != nil {
		if errClose := file.Close(); errClose != nil {
			return nil, fmt.Errorf("secure config file: %w (close: %v)", err, errClose)
		}
		return nil, fmt.Errorf("secure config file: %w", err)
	}
	return file, nil
}

func openConfigPublicationLock(path string) (*os.File, error) {
	return openPrivateConfigFile(path, windows.OPEN_ALWAYS)
}

func createConfigPublicationStage(dir string) (*os.File, error) {
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		file, err := openPrivateConfigFile(filepath.Join(dir, ".config-"+hex.EncodeToString(random[:])+".tmp"), windows.CREATE_NEW)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		return file, err
	}
	return nil, fmt.Errorf("unable to allocate private config staging file")
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
