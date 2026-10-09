//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func windowsAuthTreeFixture(t *testing.T) (string, []string, *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	expected, err := privateConfigSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := expected.Owner()
	if err != nil {
		t.Fatal(err)
	}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + owner.String() + ")(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	if err = windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "auths")
	nested := filepath.Join(dir, "nested")
	if err = os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{dir, nested, filepath.Join(dir, "legacy.json"), filepath.Join(nested, "token.JSON"), filepath.Join(nested, "opaque.token")}
	for i, path := range paths {
		if i >= 2 {
			if err = os.WriteFile(path, []byte("synthetic-token"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Elevated test processes can default to an Administrators owner. Set
		// only ownership, keeping the real inherited BUILTIN\\Users read ACE.
		if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		actual := windowsAuthTreeSecurity(t, path)
		if !strings.Contains(actual.String(), "ID;") || !strings.Contains(actual.String(), ";;;BU)") {
			t.Fatalf("fixture did not inherit BUILTIN\\Users read access: %s: %s", path, actual.String())
		}
	}
	t.Cleanup(func() {
		// A deliberately aborted migration can leave unvisited children with
		// no inherited grants. Restore the known, non-link fixture entries so
		// TempDir cleanup works as a non-admin owner too.
		privateDACL, _, errDACL := expected.DACL()
		if errDACL != nil {
			t.Error(errDACL)
			return
		}
		for _, path := range paths {
			if errRestore := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				nil, nil, privateDACL, nil); errRestore != nil {
				t.Errorf("restore fixture %s: %v", path, errRestore)
			}
		}
	})
	return dir, paths, expected
}

func windowsAuthTreeSecurity(t *testing.T, path string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return actual
}

func TestWindowsStartupRestrictsExistingAuthTree(t *testing.T) {
	dir, paths, expected := windowsAuthTreeFixture(t)
	// Keep one child's broad DACL explicitly protected, proving that fixing
	// directory inheritance alone cannot satisfy the migration regression.
	owner, _, err := expected.Owner()
	if err != nil {
		t.Fatal(err)
	}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + owner.String() + ")(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := broad.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err = windows.SetNamedSecurityInfo(paths[3], windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = RestrictAuthDirForStartup(dir); err != nil {
			t.Fatal(err)
		}
		for index, path := range paths {
			if !hasPrivateConfigDACL(windowsAuthTreeSecurity(t, path), expected) {
				t.Fatalf("entry lacks current-user owner and protected exact DACL: %s", path)
			}
			if index >= 2 {
				if data, errRead := os.ReadFile(path); errRead != nil || string(data) != "synthetic-token" {
					t.Fatalf("migration changed content of %s: %q, %v", path, data, errRead)
				}
			}
		}
	}
}

func TestWindowsStartupAuthEntryFailsClosed(t *testing.T) {
	for _, ineffective := range []bool{false, true} {
		name := "setter_denied"
		if ineffective {
			name = "read_back_mismatch"
		}
		t.Run(name, func(t *testing.T) {
			dir, _, _ := windowsAuthTreeFixture(t)
			original := restrictAuthEntry
			t.Cleanup(func() { restrictAuthEntry = original })
			failedPath := ""
			restrictAuthEntry = func(handle windows.Handle, sd *windows.SECURITY_DESCRIPTOR) error {
				var info windows.ByHandleFileInformation
				if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
					return err
				}
				if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
					return original(handle, sd)
				}
				// GetFinalPathNameByHandle reports the exact refused entry without
				// reading any token bytes. Compare the filename in the error.
				var buf [1024]uint16
				n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
				if err != nil || n >= uint32(len(buf)) {
					t.Fatalf("fixture path: %v, length %d", err, n)
				}
				failedPath = filepath.Base(windows.UTF16ToString(buf[:n]))
				if ineffective {
					return nil // A successful setter is not proof of a private DACL.
				}
				return windows.ERROR_ACCESS_DENIED
			}
			err := RestrictAuthDirForStartup(dir)
			if err == nil || failedPath == "" || !strings.Contains(err.Error(), failedPath) {
				t.Fatalf("migration must fail naming the entry %q: %v", failedPath, err)
			}
			if ineffective {
				if !strings.Contains(err.Error(), "verify auth entry") {
					t.Fatalf("ineffective setter was not rejected by read-back verification: %v", err)
				}
			} else if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("lost setter failure: %v", err)
			}
		})
	}
}

func TestWindowsStartupAuthTreeRefusesReparsePoints(t *testing.T) {
	for _, kind := range []string{"file", "directory", "root"} {
		t.Run(kind, func(t *testing.T) {
			dir, _, _ := windowsAuthTreeFixture(t)
			target := t.TempDir()
			if kind == "file" {
				target = filepath.Join(target, "external.json")
				if err := os.WriteFile(target, []byte("external-token"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			before := windowsAuthTreeSecurity(t, target).String()
			link := filepath.Join(dir, "link.json")
			startupDir := dir
			if kind == "root" {
				link = filepath.Join(filepath.Dir(dir), "root-link")
				startupDir = link
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("Windows symlink privilege or developer mode required: %v", err)
			}
			if err := RestrictAuthDirForStartup(startupDir); err == nil || !strings.Contains(err.Error(), link) {
				t.Fatalf("startup did not refuse reparse entry %s: %v", link, err)
			}
			if after := windowsAuthTreeSecurity(t, target).String(); after != before {
				t.Fatalf("migration followed link and changed external target: before %s, after %s", before, after)
			}
		})
	}
}
