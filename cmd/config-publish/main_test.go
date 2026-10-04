package main

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/crypto/bcrypt"
)

// TestPublisherHashesManagementKey uses retained fixtures so it can also run in
// repair environments that prohibit fixture deletion.
func TestPublisherHashesManagementKey(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-publish-key-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	original := []byte("# snapshot\nrequest-retry: 1\n")
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	version, err := config.ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := []byte("# edited snapshot\nremote-management:\n  secret-key: 'unit-test-only-password' # retained comment\nrequest-retry: 2\nunknown-option: [one, two]\n")
	input := filepath.Join(dir, "edited.yaml")
	if err = os.WriteFile(input, edited, 0600); err != nil {
		t.Fatal(err)
	}
	oldFlags, oldArgs := flag.CommandLine, os.Args
	defer func() { flag.CommandLine = oldFlags; os.Args = oldArgs }()
	invoke := func() error {
		flag.CommandLine = flag.NewFlagSet("config-publish-test", flag.ContinueOnError)
		os.Args = []string{"config-publish", "--config", path, "--input", input, "--expected-version", version}
		return run()
	}
	if err = invoke(); err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(published, []byte("unit-test-only-password")) {
		t.Fatal("publisher persisted plaintext management key")
	}
	cfg, err := config.ParseConfigBytes(published)
	if err != nil {
		t.Fatal(err)
	}
	if err = bcrypt.CompareHashAndPassword([]byte(cfg.RemoteManagement.SecretKey), []byte("unit-test-only-password")); err != nil {
		t.Fatalf("published key is not the server bcrypt representation: %v", err)
	}
	want := bytes.Replace(edited, []byte("'unit-test-only-password'"), []byte(cfg.RemoteManagement.SecretKey), 1)
	if !bytes.Equal(published, want) {
		t.Fatalf("non-secret bytes changed: got %q want %q", published, want)
	}
	unchangedInput, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(unchangedInput, edited) {
		t.Fatalf("edited source changed: %v", err)
	}
	if err = invoke(); !errors.Is(err, config.ErrConfigConflict) {
		t.Fatalf("stale original snapshot must conflict: %v", err)
	}
	afterConflict, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(afterConflict, published) {
		t.Fatalf("conflict changed published bytes: %v", err)
	}
}
func TestPublicationGuideMatchesCLI(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	guide, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../docs/config-publication.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"--config", "--input", "--expected-version", `sha256sum "$work/original.yaml"`, "CLI_PROXY_CONFIG_DIR", "fresh snapshot and reapplication", "file-backed", "4527"} {
		if !strings.Contains(string(guide), text) {
			t.Errorf("publication guide missing %q", text)
		}
	}
}

func TestPublisherUsesCompleteServerValidation(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-relay", true: "valid"}[valid], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			original := []byte("request-retry: 1\n")
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			version, err := config.ConfigFileVersion(path)
			if err != nil {
				t.Fatal(err)
			}
			edited := []byte("codex: {live-media-relay: {enabled: true, max-sessions: -1}}\n")
			if valid {
				edited = []byte("request-retry: 2\n")
			}
			input := filepath.Join(t.TempDir(), "edited.yaml")
			if err := os.WriteFile(input, edited, 0600); err != nil {
				t.Fatal(err)
			}
			oldFlags, oldArgs := flag.CommandLine, os.Args
			defer func() { flag.CommandLine = oldFlags; os.Args = oldArgs }()
			flag.CommandLine = flag.NewFlagSet("config-publish-test", flag.ContinueOnError)
			os.Args = []string{"config-publish", "--config", path, "--input", input, "--expected-version", version}
			err = run()
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			after, verErr := config.ConfigFileVersion(path)
			if verErr != nil {
				t.Fatal(verErr)
			}
			if valid {
				if err != nil || !bytes.Equal(got, edited) || after == version {
					t.Fatalf("valid publication failed: %v %q", err, got)
				}
				if _, err := config.LoadConfig(path); err != nil {
					t.Fatal(err)
				}
			} else {
				if err == nil {
					t.Fatal("publisher accepted config rejected by server loader")
				}
				if !bytes.Equal(got, original) || after != version {
					t.Fatal("rejected publication changed bytes or version")
				}
			}
		})
	}
}
