//go:build windows

package misc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func windowsAuthUser(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	return user.User.Sid
}

// This only installs test fixtures; production ACL policy belongs to config.
func windowsAuthFixtureDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("fixture descriptor: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("fixture DACL: %v", err)
	}
	if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		windowsAuthUser(t), nil, dacl, nil); err != nil {
		t.Fatalf("install fixture DACL: %v", err)
	}
}

func windowsAuthDescriptor(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read descriptor for %s: %v", path, err)
	}
	return sd
}

func windowsAuthAssertPrivate(t *testing.T, path string) {
	t.Helper()
	sd := windowsAuthDescriptor(t, path)
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(windowsAuthUser(t)) {
		t.Fatalf("owner is not current user: %v, descriptor %s", err, sd.String())
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 {
		t.Fatalf("DACL is not present and protected: control %#x, %v", control, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("missing DACL: %v", err)
	}
	expected, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + windowsAuthUser(t).String() + ")")
	if err != nil {
		t.Fatalf("expected descriptor: %v", err)
	}
	// Compare all ACEs exactly, ignoring only descriptor control bookkeeping
	// (e.g. AI). Inherited ACEs, other principals and inheritable grants fail.
	actualText, expectedText := sd.String(), expected.String()
	actualStart, expectedStart := strings.Index(actualText, "("), strings.Index(expectedText, "(")
	if actualStart < 0 || expectedStart < 0 || actualText[actualStart:] != expectedText[expectedStart:] {
		t.Fatalf("DACL grants = %s, want %s", actualText, expectedText)
	}
}

func windowsAuthBroadInheritedDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sid := windowsAuthUser(t).String()
	windowsAuthFixtureDACL(t, root, "D:P(A;OICI;FA;;;"+sid+")(A;OICI;FA;;;WD)")
	dir := filepath.Join(root, "auth")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	// An elevated token can default to an Administrators owner. Set only the
	// fixture owner, leaving the real inherited broad DACL unchanged.
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, windowsAuthUser(t), nil, nil, nil); err != nil {
		t.Fatalf("fixture owner: %v", err)
	}
	sd := windowsAuthDescriptor(t, dir)
	if !strings.Contains(sd.String(), "ID;") {
		t.Fatalf("fixture did not inherit ACEs: %s", sd.String())
	}
	if !strings.Contains(sd.String(), ";;;WD)") {
		t.Fatalf("fixture has no broad Everyone grant: %s", sd.String())
	}
	return dir
}

func windowsAuthAssertOnlyTarget(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "auth.json" {
		t.Fatalf("expected only target, no secret temp: entries %v, %v", entries, err)
	}
}

func TestWindowsAuthAtomicPrivateNewAndRewritten(t *testing.T) {
	for _, rewrite := range []bool{false, true} {
		name := "new"
		if rewrite {
			name = "rewrite legacy broad DACL"
		}
		t.Run(name, func(t *testing.T) {
			dir := windowsAuthBroadInheritedDir(t)
			path := filepath.Join(dir, "auth.json")
			if rewrite {
				if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
					t.Fatalf("seed: %v", err)
				}
				// Keep a wide explicit protected target DACL: tightening the
				// directory alone must not make this regression pass.
				windowsAuthFixtureDACL(t, path, "D:P(A;;FA;;;"+windowsAuthUser(t).String()+")(A;;FA;;;WD)")
			}
			if err := WriteAuthFileAtomic(path, []byte("new-token")); err != nil {
				t.Fatalf("atomic write: %v", err)
			}
			windowsAuthAssertPrivate(t, path)
			windowsAuthAssertPrivate(t, dir)
			if got, err := os.ReadFile(path); err != nil || string(got) != "new-token" {
				t.Fatalf("content = %q, %v", got, err)
			}
			windowsAuthAssertOnlyTarget(t, dir)
		})
	}
}

func TestWindowsAuthPrivateStageBeforeTokenBytes(t *testing.T) {
	dir := windowsAuthBroadInheritedDir(t)
	stage, err := createPrivateAuthTemp(dir)
	if err != nil {
		t.Fatalf("create stage: %v", err)
	}
	t.Cleanup(func() {
		if err := stage.Close(); err != nil {
			t.Errorf("close stage: %v", err)
		}
		if err := os.Remove(stage.Name()); err != nil {
			t.Errorf("remove stage: %v", err)
		}
	})
	info, err := stage.Stat()
	if err != nil || info.Size() != 0 {
		t.Fatalf("stage should be empty: %v, %v", info, err)
	}
	windowsAuthAssertPrivate(t, stage.Name())
}

func TestWindowsAuthRestrictDirectory(t *testing.T) {
	dir := windowsAuthBroadInheritedDir(t)
	if err := RestrictAuthDir(dir); err != nil {
		t.Fatalf("restrict directory: %v", err)
	}
	windowsAuthAssertPrivate(t, dir)
}

func TestWindowsAuthReadOnlyTargetPreserved(t *testing.T) {
	dir := windowsAuthBroadInheritedDir(t)
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	windowsAuthFixtureDACL(t, path, "D:P(A;;FA;;;"+windowsAuthUser(t).String()+")(A;;FA;;;WD)")
	before := windowsAuthDescriptor(t, path).String()
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("read-only target: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Errorf("restore target attributes: %v", err)
		}
	})
	if err := WriteAuthFileAtomic(path, []byte("new-token")); err == nil {
		t.Fatal("expected read-only replacement refusal")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old-token" {
		t.Fatalf("existing target changed: %q, %v", got, err)
	}
	if after := windowsAuthDescriptor(t, path).String(); after != before {
		t.Fatalf("existing target DACL changed: before %s, after %s", before, after)
	}
	windowsAuthAssertOnlyTarget(t, dir)
}

func TestWindowsAuthDirectoryACLDenialPreservesTarget(t *testing.T) {
	dir := windowsAuthBroadInheritedDir(t)
	path := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(path, []byte("old-token"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	windowsAuthFixtureDACL(t, path, "D:P(A;;FA;;;"+windowsAuthUser(t).String()+")(A;;FA;;;WD)")
	before := windowsAuthDescriptor(t, path).String()
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Keep a pre-authorized handle solely to restore the denial fixture, even
	// though subsequent opens requesting WRITE_DAC will fail.
	handle, err := windows.CreateFile(name, windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open fixture recovery handle: %v", err)
	}
	original := windowsAuthDescriptor(t, dir)
	t.Cleanup(func() {
		dacl, _, err := original.DACL()
		if err != nil {
			t.Errorf("original DACL: %v", err)
		} else if err = windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION,
			nil, nil, dacl, nil); err != nil {
			t.Errorf("restore directory DACL: %v", err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close fixture handle: %v", err)
		}
	})
	sid := windowsAuthUser(t).String()
	// OWNER RIGHTS suppresses the owner's implicit WRITE_DAC grant so this
	// fixture exercises an actual ACL refusal even when running as the owner.
	windowsAuthFixtureDACL(t, dir, "D:P(D;;WD;;;"+sid+")(A;;RC;;;OW)(A;;FA;;;"+sid+")")
	if err := WriteAuthFileAtomic(path, []byte("new-token")); err == nil || !strings.Contains(err.Error(), "restrict auth directory") {
		t.Fatalf("expected directory WRITE_DAC refusal before staging, got %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old-token" {
		t.Fatalf("existing target changed: %q, %v", got, err)
	}
	if after := windowsAuthDescriptor(t, path).String(); after != before {
		t.Fatalf("existing target DACL changed: before %s, after %s", before, after)
	}
	windowsAuthAssertOnlyTarget(t, dir)
}
