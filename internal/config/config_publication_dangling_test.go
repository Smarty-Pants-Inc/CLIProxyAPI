package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigAuthoritativePublicationSymlinks(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "dangling-refused"
		if existing {
			name = "existing-target-published"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target.yaml")
			alias := filepath.Join(dir, "alias.yaml")
			if existing {
				if err := os.WriteFile(target, []byte("debug: false\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("target.yaml", alias); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			body := []byte("debug: true\n")
			err := WriteConfigAtomic(alias, body)
			if existing {
				if err != nil {
					t.Fatal(err)
				}
				got, errRead := os.ReadFile(target)
				if errRead != nil || !bytes.Equal(got, body) {
					t.Errorf("target publication got=%q err=%v", got, errRead)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "dangling symlink") {
					t.Errorf("dangling alias save error=%v, want clear refusal", err)
				}
				if _, errStat := os.Lstat(target); !os.IsNotExist(errStat) {
					t.Errorf("target touched: %v", errStat)
				}
				entries, errRead := os.ReadDir(dir)
				if errRead != nil || len(entries) != 1 {
					t.Errorf("refused save created artifacts: %v %v", entries, errRead)
				}
			}
			link, errLink := os.Readlink(alias)
			if errLink != nil || link != "target.yaml" {
				t.Errorf("alias changed: target=%q err=%v", link, errLink)
			}
			if _, errLock := os.Lstat(alias + ".lock"); !os.IsNotExist(errLock) {
				t.Errorf("alias-specific lock created: %v", errLock)
			}
		})
	}
}
