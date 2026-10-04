package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

// ErrConfigConflict means the config changed after the caller read its version.
var ErrConfigConflict = errors.New("config changed since it was read")

// ErrConfigVersionRequired means a replacement needs a version from its source read.
var ErrConfigVersionRequired = errors.New("config version required: load the config or supply its content hash")

// ConfigFileVersion returns the content hash used for compare-and-swap publication.
func ConfigFileVersion(configFile string) (string, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return "", err
	}
	return configVersion(data), nil
}

func configVersion(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func canonicalConfigFile(configFile string) (string, error) {
	if configFile == "" {
		return "", fmt.Errorf("config file path is empty")
	}
	path, err := filepath.Abs(configFile)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}

func withConfigFileLock(configFile string, fn func(string) error) error {
	configFile, err := canonicalConfigFile(configFile)
	if err != nil {
		return err
	}
	lockFile, err := os.OpenFile(configFile+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := lockFile.Close(); errClose != nil {
			log.WithError(errClose).Error("failed to close config lock")
		}
	}()
	if err = lockConfigFile(lockFile); err != nil {
		return err
	}
	defer func() {
		if errUnlock := unlockConfigFile(lockFile); errUnlock != nil {
			log.WithError(errUnlock).Error("failed to release config lock")
		}
	}()
	return fn(configFile)
}

// AtomicWriteConfig creates a config atomically; replacing an existing file requires CAS.
func AtomicWriteConfig(configFile string, data []byte) error {
	return withConfigFileLock(configFile, func(configFile string) error {
		if _, errStat := os.Stat(configFile); errStat == nil {
			return ErrConfigVersionRequired
		} else if !os.IsNotExist(errStat) {
			return errStat
		}
		return atomicWriteConfigUnlocked(configFile, data)
	})
}

// AtomicWriteConfigCAS publishes bytes only if the file still has expectedVersion.
func AtomicWriteConfigCAS(configFile string, data []byte, expectedVersion string) (string, error) {
	var version string
	err := withConfigFileLock(configFile, func(configFile string) error {
		if expectedVersion == "" {
			return ErrConfigVersionRequired
		}
		current, errRead := os.ReadFile(configFile)
		if errRead != nil {
			return errRead
		}
		if configVersion(current) != expectedVersion {
			return ErrConfigConflict
		}
		if errWrite := atomicWriteConfigUnlocked(configFile, data); errWrite != nil {
			return errWrite
		}
		published, errPublished := os.ReadFile(configFile)
		if errPublished != nil {
			return errPublished
		}
		version = configVersion(published)
		return nil
	})
	return version, err
}

func atomicWriteConfigUnlocked(configFile string, data []byte) error {
	dir := filepath.Dir(configFile)
	mode := os.FileMode(0o644)
	if info, err := os.Stat(configFile); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if errRemove := os.Remove(tmpName); errRemove != nil && !os.IsNotExist(errRemove) {
			log.WithError(errRemove).Error("failed to remove config temporary file")
		}
	}()
	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, configFile); err != nil {
		return err
	}
	return syncConfigDir(dir)
}
