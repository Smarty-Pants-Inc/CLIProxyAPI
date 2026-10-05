//go:build windows

package config

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeStagingPrivateAtCreation(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-native-create-")
	if err != nil {
		t.Fatal(err)
	}
	// A broadly inherited parent grant must not reach the empty file at creation.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	file, err := createConfigStaging(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	assertNativeOwnerOnly(t, file.Name())
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("staging not empty: %v %v", info, err)
	}
}
