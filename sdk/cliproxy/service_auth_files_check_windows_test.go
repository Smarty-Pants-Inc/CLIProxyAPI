//go:build windows

package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"golang.org/x/sys/windows"
)

func authFilesWindowsUser(t *testing.T) (*windows.SID, string) {
	t.Helper()
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
	return user.User.Sid, account
}

func setAuthFilesWindowsDACL(t *testing.T, path, sddl string, protected bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
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
	flags := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if protected {
		flags = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, flags, owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func authFilesWindowsSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}

func TestWindowsServiceAuthFilesStartup(t *testing.T) {
	owner, account := authFilesWindowsUser(t)
	sid := owner.String()
	for _, tc := range []struct {
		name, fileDACL string
		refused        bool
	}{
		{"explicit Users read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)", true},
		{"owner only", "D:P(A;;FA;;;" + sid + ")", false},
		// CreateFileW implicitly asks for SYNCHRONIZE and FILE_READ_ATTRIBUTES;
		// an owner ACE granting only RC therefore refuses startup fail-closed.
		{"read control only", "D:P(A;;RC;;;" + sid + ")", true},
		{"null DACL", "D:PNO_ACCESS_CONTROL", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			setAuthFilesWindowsDACL(t, dir, "O:"+sid+"D:P(A;OICI;FA;;;"+sid+")", true)
			beforeDir := authFilesWindowsSecurity(t, dir).String()
			file := filepath.Join(dir, "auth.json")
			if err := os.WriteFile(file, []byte("synthetic fixture, not a credential"), 0600); err != nil {
				t.Fatal(err)
			}
			setAuthFilesWindowsDACL(t, file, "O:"+sid+tc.fileDACL, true)
			before := authFilesWindowsSecurity(t, file).String()
			var events []string
			s, stop := newAuthFilesStartupProbe(dir, &events)
			err := s.Run(context.Background())
			if tc.refused {
				fix := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "%s:F"`, file, account)
				if err == nil || !strings.Contains(err.Error(), file) || !strings.Contains(err.Error(), fix) || !strings.Contains(err.Error(), fmt.Sprintf(`icacls "%s" /reset`, file)) {
					t.Fatalf("startup must refuse with file and exact fix command: %v", err)
				}
				if len(events) != 0 || len(s.coreManager.List()) != 0 {
					t.Fatalf("unsafe auth file reached a loader: %v", events)
				}
			} else if !errors.Is(err, stop) || !reflect.DeepEqual(events, []string{"core load", "token load", "API key load"}) {
				t.Fatalf("private auth file did not pass startup check: err=%v events=%v", err, events)
			}
			if after := authFilesWindowsSecurity(t, file).String(); after != before {
				t.Fatalf("startup check changed file ACL: before %s, after %s", before, after)
			}
			if tc.refused {
				if after := authFilesWindowsSecurity(t, dir).String(); after != beforeDir {
					t.Fatalf("refused startup changed directory ACL: before %s, after %s", beforeDir, after)
				}
			}
		})
	}
}

func TestWindowsServiceAuthFilesInheritedOwnerOnly(t *testing.T) {
	owner, _ := authFilesWindowsUser(t)
	sid := owner.String()
	dir := t.TempDir()
	// The file starts with inherited broad access from an unrestricted auth
	// directory. The pre-check ignores those inherited ACEs; RestrictAuthDir
	// replaces them with owner-only OI/CI access before the full check.
	setAuthFilesWindowsDACL(t, dir, "O:"+sid+"D:AI(A;OICI;FA;;;"+sid+")(A;OICI;FR;;;BU)", false)
	file := filepath.Join(dir, "inherited.json")
	if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	var events []string
	s, stop := newAuthFilesStartupProbe(dir, &events)
	if err := s.Run(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("inherited owner-only file did not pass startup check: %v", err)
	}
	if !reflect.DeepEqual(events, []string{"core load", "token load", "API key load"}) {
		t.Fatalf("startup did not reach loaders: %v", events)
	}
	sd := authFilesWindowsSecurity(t, file)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("expected one inherited owner ACE: DACL=%v err=%v", dacl, err)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err = windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	trustee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceFlags&windows.INHERITED_ACE == 0 || !trustee.Equals(owner) {
		t.Fatalf("expected inherited current-user ACE: %s", sd.String())
	}
	before := sd.String()
	if err = internalconfig.CheckAuthFilesOwnerOnly(dir, false); err != nil {
		t.Fatal(err)
	}
	if after := authFilesWindowsSecurity(t, file).String(); after != before {
		t.Fatalf("read-only check changed inherited ACL: before %s, after %s", before, after)
	}
}

func TestWindowsServiceAuthFilesReparsePointRefused(t *testing.T) {
	owner, account := authFilesWindowsUser(t)
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%t", directory), func(t *testing.T) {
			dir := t.TempDir()
			sid := owner.String()
			setAuthFilesWindowsDACL(t, dir, "O:"+sid+"D:P(A;OICI;FA;;;"+sid+")", true)
			target := t.TempDir()
			if !directory {
				target = filepath.Join(target, "target.json")
				if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := authFilesWindowsSecurity(t, target).String()
			link := filepath.Join(dir, "reparse-entry")
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink requires Windows developer mode or privilege: %v", err)
			}
			var events []string
			s, _ := newAuthFilesStartupProbe(dir, &events)
			err := s.Run(context.Background())
			fix := fmt.Sprintf(`icacls "%s" /inheritance:r /grant:r "%s:F"`, link, account)
			if err == nil || !strings.Contains(err.Error(), "reparse point") || !strings.Contains(err.Error(), link) || !strings.Contains(err.Error(), fix) {
				t.Fatalf("expected reparse entry refusal and fix: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("reparse point reached auth loaders: %v", events)
			}
			if after := authFilesWindowsSecurity(t, target).String(); after != before {
				t.Fatalf("reparse refusal changed target ACL: before %s, after %s", before, after)
			}
		})
	}
}

func TestWindowsAuthFilesCheckSkipsSubdirectories(t *testing.T) {
	owner, _ := authFilesWindowsUser(t)
	sid := owner.String()
	dir := t.TempDir()
	setAuthFilesWindowsDACL(t, dir, "O:"+sid+"D:P(A;OICI;FA;;;"+sid+")", true)
	if err := internalconfig.RestrictAuthDir(dir); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "out-of-scope.json")
	if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	setAuthFilesWindowsDACL(t, file, "O:"+sid+"D:P(A;;FA;;;"+sid+")(A;;FR;;;BU)", true)
	before := authFilesWindowsSecurity(t, file).String()
	if err := internalconfig.CheckAuthFilesOwnerOnly(dir, false); err != nil {
		t.Fatalf("check recursed into nested files: %v", err)
	}
	if after := authFilesWindowsSecurity(t, file).String(); after != before {
		t.Fatalf("check changed nested file: before %s, after %s", before, after)
	}
}
