//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func assertNativeOwnerOnly(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner: %v", err)
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil || !owner.Equals(user.User.Sid) {
		t.Fatalf("owner changed: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("unprotected DACL: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("not exactly one owner ACE: %v", err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err = windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || !sid.Equals(owner) || ace.Mask != windows.STANDARD_RIGHTS_REQUIRED|windows.SYNCHRONIZE|0x1ff {
		t.Fatal("DACL grants non-owner or unexpected access")
	}
}

func TestNativePrivatePublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-native-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = AtomicWriteConfig(path, []byte("secret-key: first\n")); err != nil {
		t.Fatal(err)
	}
	assertNativeOwnerOnly(t, path)
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	oldPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := windows.CreateFile(oldPath, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(reader) }()
	if _, err = AtomicWriteConfigCAS(path, []byte("secret-key: second\n"), version); err != nil {
		t.Fatal(err)
	}
	var old [128]byte
	var count uint32
	if err = windows.ReadFile(reader, old[:], &count, nil); err != nil || string(old[:count]) != "secret-key: first\n" {
		t.Fatalf("old reader changed across replace: %q %v", old[:count], err)
	}
	assertNativeOwnerOnly(t, path)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "secret-key: second\n" {
		t.Fatalf("replace=%q %v", data, err)
	}
	sentinel := errors.New("rename refused")
	err = atomicWriteConfigWithRename(path, []byte("secret-key: third\n"), func(source, target string) error {
		assertNativeOwnerOnly(t, source)
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("rename refusal: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "secret-key: second\n" {
		t.Fatalf("original changed on refusal=%q %v", data, err)
	}
}
