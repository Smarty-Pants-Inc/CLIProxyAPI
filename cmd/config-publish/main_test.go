package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

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
