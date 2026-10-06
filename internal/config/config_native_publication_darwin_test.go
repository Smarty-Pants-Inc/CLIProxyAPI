//go:build darwin

package config

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePrivatePublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-native-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = AtomicWriteConfig(path, []byte("secret-key: first\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("new privacy: %v %v", info, err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AtomicWriteConfigCAS(path, []byte("secret-key: second\n"), version); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "secret-key: second\n" {
		t.Fatalf("replace=%q %v", data, err)
	}
	sentinel := errors.New("rename refused")
	err = atomicWriteConfigWithRename(path, []byte("secret-key: third\n"), func(source, target string) error {
		staged, errStat := os.Stat(source)
		if errStat != nil || staged.Mode().Perm() != 0600 {
			t.Fatalf("staging privacy: %v %v", staged, errStat)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("rename refusal: %v", err)
	}
	data, err = os.ReadFile(path)
	if err != nil || string(data) != "secret-key: second\n" {
		t.Fatalf("original changed on refusal=%q %v", data, err)
	}
}

func TestNativeInheritedACLDoesNotGrantReader(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-native-acl-")
	if err != nil {
		t.Fatal(err)
	}
	// Explicit native ACL grants to everyone propagate to child files unless
	// staging removes them before writing. No actual credential is involved.
	cmd := exec.Command("/bin/chmod", "+a", "everyone allow read,file_inherit,directory_inherit", dir)
	if out, errACL := cmd.CombinedOutput(); errACL != nil {
		t.Fatalf("ACL fixture: %s %v", out, errACL)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = AtomicWriteConfig(path, []byte("secret-key: fixture\n")); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("/bin/ls", "-le", path).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "everyone allow") {
		t.Fatalf("inherited grant retained: %s", out)
	}
}
