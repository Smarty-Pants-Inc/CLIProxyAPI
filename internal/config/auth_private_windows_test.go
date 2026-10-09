//go:build windows

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsRestrictAuthDir(t *testing.T) {
	dir := t.TempDir()
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := expected.Owner()
	if err != nil {
		t.Fatal(err)
	}
	permissive, err := windows.SecurityDescriptorFromString("O:" + owner.String() + "D:P(A;;FA;;;" + owner.String() + ")(A;;FA;;;WD)(A;;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := permissive.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = RestrictAuthDir(dir + string(os.PathSeparator)); err != nil {
			t.Fatal(err)
		}
		actual, errSecurity := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		if !hasPrivateConfigDACL(actual, expected) {
			t.Fatal("auth directory lacks current-user owner and protected exact DACL")
		}
	}
}

func TestWindowsRestrictAuthDirRefusesFileAndMissing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(dir, "missing")} {
		if err := RestrictAuthDir(path); err == nil {
			t.Fatalf("accepted non-directory %q", path)
		}
	}
}

func TestWindowsRestrictAuthDirFollowsConfiguredSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	// An elevated token may default newly created fixture directories to an
	// Administrators owner. The allowed symlink case requires our own target.
	owner, _, err := expected.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(target, link); err != nil {
		t.Skipf("directory symlink requires Windows developer mode or privilege: %v", err)
	}
	for _, path := range []string{link, link + string(os.PathSeparator)} {
		if err = RestrictAuthDir(path); err != nil {
			t.Fatalf("refused configured directory symlink: %v", err)
		}
	}
	after, err := windows.GetNamedSecurityInfo(target, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrivateConfigDACL(after, expected) {
		t.Fatal("configured directory symlink target lacks current-user owner and protected exact DACL")
	}
}

func TestWindowsCreatePrivateAuthTemp(t *testing.T) {
	dir := t.TempDir()
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	file, err := CreatePrivateAuthTemp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	if filepath.Dir(file.Name()) != dir || !strings.HasPrefix(filepath.Base(file.Name()), ".auth-") {
		t.Fatalf("wrong auth staging path: %q", file.Name())
	}
	info, err := file.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("auth stage must be empty before its first write: %v", err)
	}
	actual, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if !hasPrivateConfigDACL(actual, expected) {
		t.Fatal("auth staging handle lacks current-user owner and protected exact DACL")
	}
	if _, err = file.Write([]byte("synthetic-auth-token")); err != nil {
		t.Fatal(err)
	}
	// CREATE_NEW refusal must never remove a collision or its existing bytes.
	if collision, errCollision := openPrivateConfigFile(file.Name(), windows.CREATE_NEW); errCollision == nil {
		if errClose := collision.Close(); errClose != nil {
			t.Error(errClose)
		}
		t.Fatal("reopened an existing auth staging file")
	}
	data := make([]byte, len("synthetic-auth-token"))
	_, err = file.ReadAt(data, 0)
	if err != nil || string(data) != "synthetic-auth-token" {
		t.Fatalf("collision changed the existing auth stage: %v", err)
	}
}
