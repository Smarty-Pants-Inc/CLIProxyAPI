package config

import (
	"context"
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
	return withConfigFileLockContext(context.Background(), configFile, fn)
}

func withConfigFileLockContext(ctx context.Context, configFile string, fn func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	configFile, err := canonicalConfigFile(configFile)
	if err != nil {
		return err
	}
	lockFile, err := openConfigFileLock(configFile + ".lock")
	if err != nil {
		return err
	}
	defer func() {
		if errClose := lockFile.Close(); errClose != nil {
			log.WithError(errClose).Error("failed to close config lock")
		}
	}()
	info, errStat := os.Stat(configFile)
	if errStat != nil && !os.IsNotExist(errStat) {
		return errStat
	}
	if err = secureConfigLockIdentity(lockFile, info); err != nil {
		return err
	}
	if err = lockConfigFileContext(ctx, lockFile); err != nil {
		return err
	}
	defer func() {
		if errUnlock := unlockConfigFile(lockFile); errUnlock != nil {
			log.WithError(errUnlock).Error("failed to release config lock")
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(configFile)
}

// WithConfigFileLock runs fn under the shared config publication lock. Writers that
// cannot publish through AtomicWriteConfigCAS (a git worktree update) use it so they
// never interleave with a management, SDK or operator CAS publication.
func WithConfigFileLock(ctx context.Context, configFile string, fn func() error) error {
	return withConfigFileLockContext(ctx, configFile, func(string) error { return fn() })
}

// CreateConfigFile atomically creates configFile and its directory. It never replaces
// an existing file: created is false when another writer created it first.
func CreateConfigFile(configFile string, data []byte) (created bool, err error) {
	if err = os.MkdirAll(filepath.Dir(configFile), 0o700); err != nil {
		return false, err
	}
	err = AtomicWriteConfig(configFile, data)
	if errors.Is(err, ErrConfigVersionRequired) {
		return false, nil
	}
	return err == nil, err
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
	return AtomicWriteConfigCASContext(context.Background(), configFile, data, expectedVersion)
}

// AtomicWriteConfigCASContext cancels queued publication before the rename boundary.
func AtomicWriteConfigCASContext(ctx context.Context, configFile string, data []byte, expectedVersion string) (string, error) {
	var version string
	err := withConfigFileLockContext(ctx, configFile, func(configFile string) error {
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
		if errWrite := atomicWriteConfigWithContext(ctx, configFile, data, replaceConfigFile); errWrite != nil {
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
	return atomicWriteConfigWithRename(configFile, data, replaceConfigFile)
}

func atomicWriteConfigWithRename(configFile string, data []byte, rename func(string, string) error) error {
	return atomicWriteConfigWithContext(context.Background(), configFile, data, rename)
}

func atomicWriteConfigWithContext(ctx context.Context, configFile string, data []byte, rename func(string, string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(configFile)
	// Stage privately, retaining only policy-approved existing group readers.
	// Never enable inherited named-user ACLs.
	info, errStat := os.Stat(configFile)
	if errStat != nil && !os.IsNotExist(errStat) {
		return errStat
	}
	tmp, err := createConfigStaging(dir)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Remove only this transaction's unpublished inode. The live config and
	// persistent coordination lock are never cleanup targets. Do not unlink a
	// pathname that has been replaced by a different inode.
	stagingInfo, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	published := false
	defer func() {
		if errClose := tmp.Close(); errClose != nil && !errors.Is(errClose, os.ErrClosed) {
			log.WithError(errClose).Error("failed to close unpublished config staging")
		}
		if published {
			return
		}
		current, errInspect := os.Lstat(tmpName)
		if os.IsNotExist(errInspect) {
			return
		}
		if errInspect != nil || !os.SameFile(stagingInfo, current) {
			log.Error("cannot verify unpublished config staging identity for cleanup")
			return
		}
		if errRemove := os.Remove(tmpName); errRemove != nil {
			log.WithError(errRemove).Error("failed to remove unpublished config staging")
		}
	}()
	if err = secureConfigMAC(tmp, configFile, info); err == nil {
		err = secureConfigReplacement(tmp, info)
	}
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err = preserveConfigReadAccess(tmp, info); err != nil {
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
	// Once rename commits, cancellation cannot roll back a published file.
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = rename(tmpName, configFile); err != nil {
		return fmt.Errorf("atomic config publication refused (target may be a single-file bind mount or cross-device): mount a writable config directory instead; original config unchanged: %w", err)
	}
	published = true
	return syncConfigDir(dir)
}
