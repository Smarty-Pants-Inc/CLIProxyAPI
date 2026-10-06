//go:build darwin

package config

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

func TestRound4NativeOriginalDarwinDenyACLRefuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("api-keys: [fixture-original]\n")
	if err := os.WriteFile(path, original, 0640); err != nil {
		t.Fatal(err)
	}
	owner, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, ace := range []string{"user:" + owner.Username + " allow read", "everyone deny read"} {
		if output, err := exec.Command("/bin/chmod", "+a", ace, path).CombinedOutput(); err != nil {
			t.Fatalf("ACL fixture: %s %v", output, err)
		}
	}
	before, _ := os.Stat(path)
	aclBefore, err := exec.Command("/bin/ls", "-lde", path).Output()
	if err != nil {
		t.Fatal(err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AtomicWriteConfigCAS(path, []byte("api-keys: [fixture-candidate]\n"), version); err == nil {
		t.Fatal("original deny ACL discarded")
	}
	after, _ := os.Stat(path)
	raw, _ := os.ReadFile(path)
	aclAfter, err := exec.Command("/bin/ls", "-lde", path).Output()
	if err != nil || !os.SameFile(before, after) || string(raw) != string(original) || string(aclBefore) != string(aclAfter) {
		t.Fatal("refusal changed original inode, bytes or ACL")
	}
}
