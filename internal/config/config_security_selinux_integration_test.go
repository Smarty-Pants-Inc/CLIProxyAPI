//go:build linux && selinux_integration

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Requires a hosted enforcing SELinux policy granting the test identity relabel
// permission and two distinct config types. No privileged process is needed.
func TestPublicationRetainsEnforcedSELinuxType(t *testing.T) {
	enforcing, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil || string(bytes.TrimSpace(enforcing)) != "1" {
		t.Skip("requires enforcing SELinux fixture")
	}
	label := os.Getenv("CPA_TEST_SELINUX_ORIGINAL")
	if label == "" {
		t.Skip("requires policy-provided config label")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(path, "security.selinux", append([]byte(label), 0), 0); err != nil {
		t.Fatal(err)
	}
	original, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	before, err := configSELinuxLabel(original)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := os.CreateTemp(dir, ".label-check-")
	if err != nil {
		t.Fatal(err)
	}
	inherited, err := configSELinuxLabel(stage)
	_ = stage.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, inherited) {
		t.Fatal("fixture must assign different original and staging types")
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AtomicWriteConfigCAS(path, []byte("debug: true\n"), version); err != nil {
		t.Fatal(err)
	}
	published, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = published.Close() }()
	after, err := configSELinuxLabel(published)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("mandatory-access label changed: %q -> %q (%v)", before, after, err)
	}
}
