//go:build windows

package config

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAuthFileDACLTrustees(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
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
			if errCheck := authFileDACLIsOwnerOnly(sd, user.User.Sid); (errCheck != nil) != tc.wantErr {
				t.Fatalf("DACL check = %v, want error=%t: %s", errCheck, tc.wantErr, before)
			}
			if after := sd.String(); after != before {
				t.Fatalf("read-only check changed descriptor: before %s, after %s", before, after)
			}
		})
	}
	if err = authFileDACLIsOwnerOnly(nil, user.User.Sid); err == nil {
		t.Fatal("accepted missing security descriptor")
	}
}
