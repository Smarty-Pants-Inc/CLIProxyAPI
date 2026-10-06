//go:build linux

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestNonRenameableConfigRefusedWithoutTruncation(t *testing.T) {
	for _, cause := range []error{syscall.EBUSY, syscall.EXDEV} {
		t.Run(cause.Error(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			original := []byte("api-keys: [original-secret]\n")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			version, err := ConfigFileVersion(path)
			if err != nil {
				t.Fatal(err)
			}
			err = withConfigFileLock(path, func(path string) error {
				current, err := ConfigFileVersion(path)
				if err != nil {
					return err
				}
				if current != version {
					return ErrConfigConflict
				}
				return atomicWriteConfigWithRename(path, []byte("api-keys: [new-secret]\n"), func(from, to string) error {
					info, err := os.Stat(from)
					if err != nil {
						t.Fatal(err)
					}
					if info.Mode().Perm() != 0600 {
						t.Fatal("failed staging not private")
					}
					return &os.LinkError{Op: "rename", Old: from, New: to, Err: fmt.Errorf("wrapped mount error: %w", cause)}
				})
			})
			if !errors.Is(err, cause) || !strings.Contains(err.Error(), "mount a writable config directory") {
				t.Fatalf("unclear refusal: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != string(original) {
				t.Fatalf("refusal truncated original: %q %v", data, err)
			}
		})
	}
}

func TestPublicationPreservesOwnerReadOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0400); err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteConfigCAS(path, []byte("debug: true\n"), version); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0400 {
		t.Fatalf("owner permissions widened: %o", info.Mode().Perm())
	}
}
