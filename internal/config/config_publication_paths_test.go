//go:build !windows

package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigPublicationWriterPaths(t *testing.T) {
	path := publicationFixture(t)
	if err := os.WriteFile(path, []byte("debug: false\nremote-management:\n  secret-key: ''\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(path), "alias.yaml")
	if err = os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	// The raw YAML adapter's authoritative publisher must use the same canonical
	// gate even through an alias. Loading then persists the plaintext key's hash.
	if err = WriteConfigAtomic(alias, []byte("debug: true\nremote-management:\n  secret-key: synthetic-path-secret\n")); err != nil {
		t.Fatal(err)
	}
	current, err := LoadConfig(alias)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("synthetic-path-secret")) || !bytes.Contains(data, []byte("$2")) {
		t.Fatal("load-time hash persistence failed")
	}
	if err = SaveConfigPreserveComments(alias, old); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("raw replacement did not fence stale full save: %v", err)
	}
	if err = SaveConfigPreserveCommentsUpdateNestedScalar(alias, []string{"proxy-url"}, "http://synthetic.invalid"); err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(path, current); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("nested replacement did not fence stale full save: %v", err)
	}
	latest, err := LoadConfig(alias)
	if err != nil {
		t.Fatal(err)
	}
	latest.Debug = false
	if err = SaveConfigPreserveComments(alias, latest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("publication replaced symlink rather than canonical target")
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(alias + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("alias used a distinct lock: %v", err)
	}
}
