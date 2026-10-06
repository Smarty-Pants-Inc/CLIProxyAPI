//go:build windows

package config

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestRound4NativeOriginalWindowsReaderDACLRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	original := []byte("api-keys: [fixture-original]\n")
	if err := AtomicWriteConfig(path, original); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + owner.String() + ")(A;;GR;;;LS)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := policy.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	aclBefore, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteConfigCAS(path, []byte("api-keys: [fixture-candidate]\n"), version); err == nil {
		t.Fatal("original non-owner reader DACL discarded")
	}
	after, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	aclAfter, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || !os.SameFile(before, after) || string(raw) != string(original) || aclBefore.String() != aclAfter.String() {
		t.Fatal("refusal changed original inode, bytes or DACL")
	}
}
