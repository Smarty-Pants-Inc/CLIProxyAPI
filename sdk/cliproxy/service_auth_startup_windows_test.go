//go:build windows

package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"golang.org/x/sys/windows"
)

func windowsStartupAuthFixture(t *testing.T) (string, []string, *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	expected, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	broad, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FR;;;BU)")
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
		user.User.Sid, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "auths")
	nested := filepath.Join(dir, "nested")
	if err = os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{dir, nested, filepath.Join(dir, "legacy.json"), filepath.Join(nested, "legacy.json")}
	for i, path := range paths {
		if i >= 2 {
			if err = os.WriteFile(path, []byte(`{"type":"startup-test","access_token":"synthetic-token"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// Set only the fixture owner for elevated runners, preserving inherited
		// BUILTIN\\Users read access established before the service starts.
		if err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		actual, errSecurity := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		if !strings.Contains(actual.String(), "ID;") || !strings.Contains(actual.String(), ";;;BU)") {
			t.Fatalf("fixture does not have broad inherited Users read access: %s: %s", path, actual.String())
		}
	}
	return dir, paths, expected
}

func windowsStartupAssertPrivate(t *testing.T, paths []string, expected *windows.SECURITY_DESCRIPTOR) {
	t.Helper()
	owner, _, err := expected.Owner()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		actual, errSecurity := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if errSecurity != nil {
			t.Fatal(errSecurity)
		}
		actualOwner, _, errOwner := actual.Owner()
		control, _, errControl := actual.Control()
		actualText, expectedText := actual.String(), expected.String()
		actualStart, expectedStart := strings.Index(actualText, "("), strings.Index(expectedText, "(")
		if errOwner != nil || actualOwner == nil || !actualOwner.Equals(owner) ||
			errControl != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 ||
			actualStart < 0 || expectedStart < 0 || actualText[actualStart:] != expectedText[expectedStart:] {
			t.Fatalf("entry not verified owner-only/protected before loading: %s: %s", path, actualText)
		}
	}
}

func TestWindowsStartupMigratesAuthBeforeAnyLoader(t *testing.T) {
	dir, paths, expected := windowsStartupAuthFixture(t)
	assertPrivate := func() { windowsStartupAssertPrivate(t, paths, expected) }
	store := &startupAuthStore{FileTokenStore: sdkAuth.NewFileTokenStore(), beforeList: assertPrivate}
	store.SetBaseDir(dir)
	tokenProvider := &startupTokenProvider{beforeLoad: assertPrivate}
	stop := errors.New("stop after all startup auth loaders, before server or watcher")
	apiKeyProvider := &startupAPIKeyProvider{beforeLoad: assertPrivate, stop: stop}
	service := &Service{
		cfg:            &config.Config{AuthDir: dir},
		coreManager:    coreauth.NewManager(store, nil, nil),
		tokenProvider:  tokenProvider,
		apiKeyProvider: apiKeyProvider,
	}
	if err := service.Run(context.Background()); !errors.Is(err, stop) {
		t.Fatalf("startup did not reach loaders after migration: %v", err)
	}
	if store.calls != 1 || tokenProvider.calls != 1 || apiKeyProvider.calls != 1 {
		t.Fatalf("load calls: store=%d, tokens=%d, API keys=%d", store.calls, tokenProvider.calls, apiKeyProvider.calls)
	}
	auths := service.coreManager.List()
	if len(auths) != 2 {
		t.Fatalf("existing auths were not loaded after migration: %d", len(auths))
	}
	for _, auth := range auths {
		if auth.Metadata["access_token"] != "synthetic-token" {
			t.Fatalf("migration changed auth token: %s", auth.ID)
		}
	}
	if service.server != nil || service.watcher != nil {
		t.Fatal("test must stop before starting server or watcher")
	}
}

func TestWindowsStartupRestrictionFailureLoadsNothing(t *testing.T) {
	dir, paths, _ := windowsStartupAuthFixture(t)
	original := restrictAuthDir
	t.Cleanup(func() { restrictAuthDir = original })
	denied := windows.ERROR_ACCESS_DENIED
	restrictAuthDir = func(path string) error {
		if path != dir {
			t.Fatalf("startup restriction path = %q, want %q", path, dir)
		}
		return fmt.Errorf("secure auth entry %q: %w", paths[2], denied)
	}
	mustNotLoad := func() { t.Fatal("auth loader ran after startup restriction failed") }
	store := &startupAuthStore{FileTokenStore: sdkAuth.NewFileTokenStore(), beforeList: mustNotLoad}
	store.SetBaseDir(dir)
	tokenProvider := &startupTokenProvider{beforeLoad: mustNotLoad}
	apiKeyProvider := &startupAPIKeyProvider{beforeLoad: mustNotLoad}
	service := &Service{
		cfg:            &config.Config{AuthDir: dir},
		coreManager:    coreauth.NewManager(store, nil, nil),
		tokenProvider:  tokenProvider,
		apiKeyProvider: apiKeyProvider,
	}
	err := service.Run(context.Background())
	if !errors.Is(err, denied) || !strings.Contains(err.Error(), paths[2]) {
		t.Fatalf("startup must fail naming the unsecured file: %v", err)
	}
	if store.calls != 0 || tokenProvider.calls != 0 || apiKeyProvider.calls != 0 || len(service.coreManager.List()) != 0 {
		t.Fatal("startup restriction failure loaded auth tokens")
	}
	if service.server != nil || service.watcher != nil {
		t.Fatal("startup restriction failure started server or watcher")
	}
}
