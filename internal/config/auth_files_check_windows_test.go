//go:build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAuthFileDACLTrustees(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	defaultOwner, err := authFilesTokenOwner()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, dacl string
		wantErr    bool
	}{
		{"explicit owner", "D:P(A;;FA;;;" + sid + ")", false},
		{"inherited owner", "D:AI(A;ID;FA;;;" + sid + ")", false},
		{"read control only", "D:P(A;;RC;;;" + sid + ")", false},
		{"empty", "D:P", false},
		{"owner deny", "D:P(D;;FW;;;" + sid + ")(A;;FR;;;" + sid + ")", false},
		{"Users read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)", true},
		{"deny does not excuse grant", "D:P(D;;FR;;;BU)(A;;FA;;;" + sid + ")(A;;FR;;;BU)", true},
		{"foreign deny", "D:P(D;;FR;;;BU)(A;;FA;;;" + sid + ")", true},
		{"foreign write only", "D:P(A;;FA;;;" + sid + ")(A;;FW;;;BU)", true},
		{"null", "D:PNO_ACCESS_CONTROL", true},
		{"missing", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, errParse := windows.SecurityDescriptorFromString("O:" + sid + tc.dacl)
			if errParse != nil {
				t.Fatal(errParse)
			}
			before := sd.String()
			if errCheck := authFileDACLIsOwnerOnly(sd, user.User.Sid, defaultOwner, false); (errCheck != nil) != tc.wantErr {
				t.Fatalf("DACL check = %v, want error=%t: %s", errCheck, tc.wantErr, before)
			}
			if after := sd.String(); after != before {
				t.Fatalf("read-only check changed descriptor: before %s, after %s", before, after)
			}
		})
	}
	if err = authFileDACLIsOwnerOnly(nil, user.User.Sid, defaultOwner, false); err == nil {
		t.Fatal("accepted missing security descriptor")
	}
}

func TestWindowsAuthFileOwners(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	defaultOwner, err := authFilesTokenOwner()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, owner string
		wantErr     bool
	}{
		{"current user", "O:" + user.User.Sid.String(), false},
		{"token default owner", "O:" + defaultOwner.String(), false},
		{"foreign owner", "O:WD", true},
		{"missing owner", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, errParse := windows.SecurityDescriptorFromString(tc.owner + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
			if errParse != nil {
				t.Fatal(errParse)
			}
			before := sd.String()
			for _, ignoreInherited := range []bool{true, false} {
				if errCheck := authFileDACLIsOwnerOnly(sd, user.User.Sid, defaultOwner, ignoreInherited); (errCheck != nil) != tc.wantErr {
					t.Fatalf("owner check (ignoreInherited=%t) = %v, want error=%t", ignoreInherited, errCheck, tc.wantErr)
				}
			}
			if after := sd.String(); after != before {
				t.Fatalf("read-only check changed descriptor: before %s, after %s", before, after)
			}
		})
	}
}

func TestWindowsAuthFileReadControlOnlyRefusedAtOpen(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	account, domain, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "" {
		account = domain + `\` + account
	}
	sid := user.User.Sid.String()
	dir := t.TempDir()
	file := filepath.Join(dir, "auth.json")
	if err = os.WriteFile(file, []byte("synthetic fixture, not a credential"), 0600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;RC;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(file, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}

	err = CheckAuthFilesOwnerOnly(dir, false)
	fix := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "%s:F"`, file, account)
	if err == nil || !strings.Contains(err.Error(), file) || !strings.Contains(err.Error(), fix) {
		t.Fatalf("RC-only owner DACL must refuse with file and exact fix command: %v", err)
	}
}
