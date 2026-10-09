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

func authFilesWindowsTokenOwner(t *testing.T) *windows.SID {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	var size uint32
	if err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size); err != windows.ERROR_INSUFFICIENT_BUFFER {
		t.Fatalf("query token owner size: %v", err)
	}
	buffer := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size); err != nil {
		t.Fatal(err)
	}
	owner := *(**windows.SID)(unsafe.Pointer(&buffer[0]))
	if owner == nil || !owner.IsValid() {
		t.Fatal("missing or invalid token default owner")
	}
	copy, err := owner.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return copy
}

func authFilesWindowsForeignOwner(t *testing.T, user, defaultOwner *windows.SID) *windows.SID {
	t.Helper()
	groups, err := windows.GetCurrentProcessToken().GetTokenGroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups.AllGroups() {
		if group.Attributes&windows.SE_GROUP_OWNER != 0 && !group.Sid.Equals(user) && !group.Sid.Equals(defaultOwner) {
			owner, errCopy := group.Sid.Copy()
			if errCopy != nil {
				t.Fatal(errCopy)
			}
			return owner
		}
	}
	t.Skip("token has no SE_GROUP_OWNER group other than the current user or token default owner to assign as a foreign file owner")
	return nil
}

func setAuthFilesWindowsOwner(t *testing.T, path string, owner *windows.SID, skipIfDenied bool) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := windows.CloseHandle(handle); errClose != nil {
			t.Error(errClose)
		}
	}()
	if err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		if skipIfDenied && (errors.Is(err, windows.ERROR_INVALID_OWNER) || errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)) {
			t.Skipf("token cannot assign foreign file owner %s: %v", owner.String(), err)
		}
		t.Fatal(err)
	}
}

func TestWindowsServiceAuthFilesStartup(t *testing.T) {
	owner, account := authFilesWindowsUser(t)
	defaultOwner := authFilesWindowsTokenOwner(t)
	sid := owner.String()
	for _, tc := range []struct {
		name, fileDACL string
		refused        bool
	}{
		{"explicit Users read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)", true},
		{"owner only", "D:P(A;;FA;;;" + sid + ")", false},
		{"token default owner", "D:P(A;;FA;;;" + sid + ")", false},
		{"foreign owner", "D:P(A;;FA;;;" + sid + ")", true},
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
			if tc.name == "token default owner" {
				setAuthFilesWindowsOwner(t, file, defaultOwner, false)
			} else if tc.name == "foreign owner" {
				setAuthFilesWindowsOwner(t, file, authFilesWindowsForeignOwner(t, owner, defaultOwner), true)
			}
			before := authFilesWindowsSecurity(t, file).String()
			if tc.name == "owner only" || tc.name == "token default owner" || tc.name == "foreign owner" {
				for _, ignoreInherited := range []bool{true, false} {
					errCheck := internalconfig.CheckAuthFilesOwnerOnly(dir, ignoreInherited)
					if (errCheck != nil) != tc.refused {
						t.Fatalf("owner check (ignoreInherited=%t) = %v, want refused=%t", ignoreInherited, errCheck, tc.refused)
					}
					if tc.refused && !strings.Contains(errCheck.Error(), "auth file owner is neither") {
						t.Fatalf("foreign owner did not refuse at the owner check: %v", errCheck)
					}
				}
			}
			var events []string
			s, stop := newAuthFilesStartupProbe(dir, &events)
			err := s.Run(context.Background())
			if tc.refused {
				fix := fmt.Sprintf(`icacls "%s" /setowner "%s" && icacls "%s" /reset && icacls "%s" /inheritance:r /grant:r "%s:F"`, file, account, file, file, account)
				if err == nil || !strings.Contains(err.Error(), file) || !strings.Contains(err.Error(), fix) {
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
