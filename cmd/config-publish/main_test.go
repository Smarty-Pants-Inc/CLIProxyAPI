package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

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
