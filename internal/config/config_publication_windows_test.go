//go:build windows

package config

import (
	"os"
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
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{path, path + ".lock"} {
		sd, errSecurity := windows.GetNamedSecurityInfo(file, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		if sd.String() != expected.String() {
			t.Fatalf("publication file lacks protected private DACL: %s", file)
		}
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

func TestWindowsConfigPublicationLockExcludesOtherHandle(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-windows-lock-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml.lock")
	first, err := openConfigPublicationLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if errClose := first.Close(); errClose != nil {
			t.Error(errClose)
		}
	}()
	second, err := openConfigPublicationLock(path)
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
