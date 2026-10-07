package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"

	cpaconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// Remote-backed stores mirror config.yaml into a local spool. Every local write goes
// through the shared config lock/CAS boundary, so it cannot overwrite a concurrent
// management, SDK or operator publication (CLIProxyAPI#51).

// localConfigVersion returns the CAS version of the local config, or "" when it is absent.
func localConfigVersion(path string) (string, error) {
	version, err := cpaconfig.ConfigFileVersion(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return version, err
}

// publishRemoteConfig replaces the local config with remote bytes only while it still has
// prior, the version read before the remote fetch. A concurrent local change wins and the
// sync fails with ErrConfigConflict.
func publishRemoteConfig(ctx context.Context, path string, data []byte, prior string) error {
	if prior == "" {
		created, err := cpaconfig.CreateConfigFile(path, data)
		if err == nil && !created {
			return cpaconfig.ErrConfigConflict
		}
		return err
	}
	_, err := cpaconfig.AtomicWriteConfigCASContext(ctx, path, data, prior)
	return err
}

// seedLocalConfig creates the local config from the example template, or empty when no
// template is given. An existing config, including one created concurrently, is kept.
func seedLocalConfig(path, example string) error {
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var data []byte
	if example != "" {
		var err error
		if data, err = os.ReadFile(example); err != nil {
			return err
		}
	}
	_, err := cpaconfig.CreateConfigFile(path, data)
	return err
}

// seedRemoteConfig uploads the local config when the remote has none. It holds the shared
// config lock from the read through the upload, so no CAS publication can land in between.
// After the upload it re-verifies the local revision: if a writer that bypasses the lock
// (a text editor) changed the file, the stale upload is superseded by a retry with the
// newer bytes.
func seedRemoteConfig(ctx context.Context, path string, upload func([]byte) error) error {
	return cpaconfig.WithConfigFileLock(ctx, path, func() error {
		for attempt := 0; attempt < seedRemoteConfigAttempts; attempt++ {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err = upload(data); err != nil {
				return err
			}
			current, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Equal(current, data) {
				return nil
			}
		}
		return fmt.Errorf("local config kept changing during the seed upload: %w", cpaconfig.ErrConfigConflict)
	})
}

const seedRemoteConfigAttempts = 3
