//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsAuthTempSecurityRefusalCleanup(t *testing.T) {
	// A deliberately incompatible expected owner makes the real handle-based
	// validation fail deterministically, without requiring ownership privileges.
	foreign, err := windows.SecurityDescriptorFromString("O:S-1-5-21-1-2-3-1009D:P(A;;FA;;;S-1-5-21-1-2-3-1009)")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		disposition uint32
		removed     bool
	}{
		{"new empty stage removed", windows.CREATE_NEW, true},
		{"existing file preserved", windows.OPEN_ALWAYS, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			file, errCreate := CreatePrivateAuthTemp(dir)
			if errCreate != nil {
				t.Fatal(errCreate)
			}
			path := file.Name()
			if !tc.removed {
				if _, errWrite := file.Write([]byte("synthetic-existing-auth")); errWrite != nil {
					if errClose := file.Close(); errClose != nil {
						t.Error(errClose)
					}
					t.Fatal(errWrite)
				}
			}
			if secured, errSecure := securePrivateConfigFile(file, tc.disposition, foreign); errSecure == nil {
				if errClose := secured.Close(); errClose != nil {
					t.Error(errClose)
				}
				t.Fatal("accepted an incompatible expected owner")
			}
			if tc.removed {
				entries, errReadDir := os.ReadDir(dir)
				if errReadDir != nil || len(entries) != 0 {
					t.Fatalf("refused empty auth stage left behind: %v, entries=%v", errReadDir, entries)
				}
			} else {
				data, errRead := os.ReadFile(filepath.Clean(path))
				if errRead != nil || string(data) != "synthetic-existing-auth" {
					t.Fatalf("security refusal modified an existing auth file: %v", errRead)
				}
			}
		})
	}
}
