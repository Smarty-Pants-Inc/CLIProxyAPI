//go:build windows

package management

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsManagementUploadValidationPermissiveParent(t *testing.T) {
	dir := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	// Everyone can read inherited child files, while this user keeps full access.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FRFX;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	project := func(sd *windows.SECURITY_DESCRIPTOR) string {
		t.Helper()
		acl, _, errACL := sd.DACL()
		if errACL != nil {
			t.Fatal(errACL)
		}
		p, errNew := windows.NewSecurityDescriptor()
		if errNew != nil {
			t.Fatal(errNew)
		}
		if errSet := p.SetDACL(acl, true, false); errSet != nil {
			t.Fatal(errSet)
		}
		if errSet := p.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); errSet != nil {
			t.Fatal(errSet)
		}
		return p.String()
	}
	if project(actual) != project(descriptor) {
		t.Fatalf("permissive parent DACL not installed: %s", actual.String())
	}
	// Run the actual upload handler, including transient event and leaked-lock
	// checks, with a privately published live config in the permissive parent.
	testManagementUploadValidationNoArtifacts(t, dir)
	expected, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"config.yaml", "config.yaml.lock"} {
		sd, errSecurity := windows.GetNamedSecurityInfo(filepath.Join(dir, name), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		owner, _, errOwner := sd.Owner()
		control, _, errControl := sd.Control()
		if errOwner != nil || owner == nil || !owner.Equals(user.User.Sid) || errControl != nil || control&windows.SE_DACL_PROTECTED == 0 || project(sd) != project(expected) {
			t.Errorf("upload publication lacks private current-user owner/DACL: %s", name)
		}
	}
}
