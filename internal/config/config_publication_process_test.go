//go:build !windows

package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Use retained private fixtures: no implicit cleanup of shared state.
func publicationFixture(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "config-publication-test-")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "config.yaml")
}

func TestConfigPublicationTwoProcess(t *testing.T) {
	if path := os.Getenv("CONFIG_PUBLICATION_CHILD"); path != "" {
		publicationRevoker(t, path)
		return
	}
	original := []byte("debug: false\napi-keys: [synthetic-revoked-client]\nremote-management:\n  secret-key: synthetic-old-management\n")
	for _, newer := range []string{
		"debug: false\napi-keys: []\nremote-management:\n  secret-key: synthetic-old-management\n",
		"debug: false\napi-keys: [synthetic-revoked-client]\nremote-management:\n  secret-key: synthetic-rotated-management\n",
	} {
		path := publicationFixture(t)
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestConfigPublicationTwoProcess$")
		cmd.Env = append(os.Environ(), "CONFIG_PUBLICATION_CHILD="+path, "CONFIG_PUBLICATION_NEW="+newer)
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(output)
		var gateState string
		// Gate the saver after its exact final source read, before comparison and
		// publication. A separate process attempts the canonical sibling lock here.
		saveErr := writeConfigRevisionWithRead(path, original, sourceRevision(original), func(path string) ([]byte, error) {
			data, errRead := os.ReadFile(path)
			if _, errWrite := fmt.Fprintln(input, "revoke"); errWrite != nil {
				return nil, errWrite
			}
			if !scanner.Scan() {
				return nil, fmt.Errorf("revoker failed to report gate")
			}
			gateState = scanner.Text()
			return data, errRead
		})
		_ = input.Close()
		for scanner.Scan() { /* Drain child test output before waiting. */
		}
		errWait := cmd.Wait()
		if errWait != nil {
			t.Fatalf("revoker: %v: %s", errWait, &stderr)
		}
		if saveErr != nil && !errors.Is(saveErr, ErrStaleConfig) {
			t.Fatal(saveErr)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, []byte(newer)) {
			t.Errorf("completed revocation was overwritten (gate=%s, save=%v): %s", gateState, saveErr, data)
		}
		t.Logf("final-read gate=%s; newer bytes preserved=%t", gateState, bytes.Equal(data, []byte(newer)))
	}
}

func publicationRevoker(t *testing.T, path string) {
	t.Helper()
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		t.Fatal("missing final-read gate")
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	}()
	err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	blocked := errors.Is(err, unix.EWOULDBLOCK)
	if blocked {
		fmt.Println("blocked-by-saver")
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX)
	}
	if err != nil {
		t.Fatal(err)
	}
	// The child holds the cross-process gate while completing credential revocation.
	file, err := os.CreateTemp(filepath.Dir(path), ".revocation-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString(os.Getenv("CONFIG_PUBLICATION_NEW")); err != nil {
		t.Fatal(err)
	}
	if err = file.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(file.Name(), path); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err = dir.Sync(); err != nil {
		t.Fatal(err)
	}
	if err = dir.Close(); err != nil {
		t.Fatal(err)
	}
	if !blocked {
		fmt.Println("revoked-before-saver-publication")
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestConfigPublicationUncontended(t *testing.T) {
	path := publicationFixture(t)
	if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []bool{true, false, true} {
		cfg.Debug = value
		if err = SaveConfigPreserveComments(path, cfg); err != nil {
			t.Fatal(err)
		}
		loaded, errLoad := LoadConfig(path)
		if errLoad != nil {
			t.Fatal(errLoad)
		}
		if loaded.Debug != value {
			t.Fatal("uncontended publication lost update")
		}
	}
}
