//go:build windows

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivateAtomicConfigPublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-windows-publication-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, []byte("remote-management:\n  secret-key: synthetic-startup-key\nrequest-retry: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeBcrypt(cfg.RemoteManagement.SecretKey) {
		t.Fatal("plaintext startup key not hashed")
	}
	for retry := 2; retry <= 3; retry++ {
		cfg.RequestRetry = retry
		if err = SaveConfigPreserveComments(path, cfg); err != nil {
			t.Fatal(err)
		}
	}
	if err = WriteConfigAtomic(path, []byte("request-retry: 4\n")); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadConfig(path)
	if err != nil || cfg.RequestRetry != 4 {
		t.Fatalf("raw publication: %v", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".lock"} {
		sd, errSecurity := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		if !hasPrivateConfigDACL(sd, expected) {
			t.Fatalf("publication file lacks current-user owner and protected private DACL: %s", file)
		}
	}
}

func TestWindowsPrivateConfigDACLMetadata(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, sddl string
		want       bool
	}{
		{"exact", "O:" + sid + "D:P(A;;FA;;;" + sid + ")", true},
		{"auto inherited metadata", "O:" + sid + "D:PAI(A;;FA;;;" + sid + ")", true},
		{"matching owner and group metadata", "O:" + sid + "G:BAD:PAI(A;;FA;;;" + sid + ")", true},
		{"Administrators owner", "O:BAG:BAD:PAI(A;;FA;;;" + sid + ")", false},
		{"another-user owner", "O:S-1-5-21-1-2-3-1009D:P(A;;FA;;;" + sid + ")", false},
		{"missing owner", "G:BAD:P(A;;FA;;;" + sid + ")", false},
		{"wrong user ACE", "D:P(A;;FA;;;S-1-5-21-1-2-3-1009)", false},
		{"system trustee", "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)", false},
		{"deny ACE", "D:P(D;;FA;;;" + sid + ")", false},
		{"unprotected", "D:(A;;FA;;;" + sid + ")", false},
		{"null", "D:PNO_ACCESS_CONTROL", false},
		{"empty", "D:P", false},
		{"extra trustee", "D:P(A;;FA;;;" + sid + ")(A;;FA;;;WD)", false},
		{"inherited ACE", "D:P(A;ID;FA;;;" + sid + ")", false},
		{"inheritable ACE", "D:P(A;OI;FA;;;" + sid + ")", false},
		{"partial access", "D:P(A;;FR;;;" + sid + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sddl := tc.sddl
			// All DACL refusal cases have a matching owner so they still test
			// the DACL, rather than failing early on missing ownership.
			if len(sddl) > 0 && sddl[0] == 'D' {
				sddl = "O:" + sid + sddl
			}
			actual, errParse := windows.SecurityDescriptorFromString(sddl)
			if errParse != nil {
				t.Fatal(errParse)
			}
			if got := hasPrivateConfigDACL(actual, expected); got != tc.want {
				t.Fatalf("private DACL = %t, want %t (descriptor: %s)", got, tc.want, actual.String())
			}
		})
	}
}

func TestWindowsAtomicPublicationRefusesReadOnlyDestination(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-windows-readonly-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	original := []byte("request-retry: 1\n")
	if err = WriteConfigAtomic(path, original); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_READONLY); err != nil {
		t.Fatal(err)
	}
	if err = WriteConfigAtomic(path, []byte("request-retry: 2\n")); err == nil {
		t.Fatal("read-only publication unexpectedly succeeded")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != string(original) {
		t.Fatalf("refused publication modified original: %v", err)
	}
}

func TestWindowsConfigPublicationLockExcludesOtherProcess(t *testing.T) {
	if path := os.Getenv("WINDOWS_CONFIG_LOCK_CHILD"); path != "" {
		file, err := os.OpenFile(path, os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if errClose := file.Close(); errClose != nil {
				t.Error(errClose)
			}
		}()
		err = windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
		if err != windows.ERROR_LOCK_VIOLATION {
			t.Fatalf("child lock = %v, want lock violation", err)
		}
		return
	}
	dir, err := os.MkdirTemp("", "config-windows-process-lock-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	if err = lockConfigPublication(file); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errUnlock := unlockConfigPublication(file); errUnlock != nil {
			t.Error(errUnlock)
		}
	}()
	child := exec.Command(os.Args[0], "-test.run=^TestWindowsConfigPublicationLockExcludesOtherProcess$")
	child.Env = append(os.Environ(), "WINDOWS_CONFIG_LOCK_CHILD="+path)
	if output, errRun := child.CombinedOutput(); errRun != nil {
		t.Fatalf("child process: %v: %s", errRun, output)
	}
}

func TestWindowsConfigPublicationLockExcludesOtherHandle(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-windows-lock-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := first.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	second, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := second.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	if err = lockConfigPublication(first); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errUnlock := unlockConfigPublication(first); errUnlock != nil {
			t.Error(errUnlock)
		}
	}()
	err = windows.LockFileEx(windows.Handle(second.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
	if err != windows.ERROR_LOCK_VIOLATION {
		t.Fatalf("second handle lock = %v, want lock violation", err)
	}
}
