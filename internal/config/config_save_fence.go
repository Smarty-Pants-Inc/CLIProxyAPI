package config

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	log "github.com/sirupsen/logrus"
)

// ErrStaleConfig means a save has no source revision or the file no longer
// matches it. Reload the configuration and reapply the intended change.
// Errors using this sentinel do not include config contents, keys or digests.
var ErrStaleConfig = errors.New("config source revision is stale or untracked; reload before saving")

// Value metadata is intentional: saving one snapshot must not advance copies.
// It is private and is never included in YAML or JSON.
type configSourceRevision struct {
	digest  [sha256.Size]byte
	tracked bool
}

func sourceRevision(data []byte) configSourceRevision {
	return configSourceRevision{digest: sha256.Sum256(data), tracked: true}
}
func (r configSourceRevision) matches(data []byte) bool {
	return r.tracked && r.digest == sha256.Sum256(data)
}

// Serialize in-process snapshot updates as well as publication.
var configSaveMu sync.Mutex

// writeConfigRevision checks and publishes under the operator publisher's stable
// canonical-path sibling lock. Callers advance metadata only after success.
func writeConfigRevision(path string, data []byte, expected configSourceRevision) error {
	return writeConfigRevisionWithRead(path, data, expected, os.ReadFile)
}

// The read seam lets tests gate the exact final validation/publication boundary.
func writeConfigRevisionWithRead(path string, data []byte, expected configSourceRevision, read func(string) ([]byte, error)) error {
	return withConfigPublicationLock(path, func(path string) error {
		current, err := read(path)
		if os.IsNotExist(err) {
			return ErrStaleConfig
		}
		if err != nil {
			return err
		}
		if !expected.matches(current) {
			return ErrStaleConfig
		}
		return publishConfigLocked(path, data)
	})
}

// WriteConfigAtomic is an authoritative raw replacement, not a snapshot save.
// It shares the lock and atomic publication protocol with revision-checked saves.
func WriteConfigAtomic(path string, data []byte) error {
	return withConfigPublicationLock(path, func(path string) error {
		return publishConfigLocked(path, data)
	})
}

// Resolve symlinks before choosing the lock so aliases share one boundary.
// This matches the canonical-path protocol of cmd/config-publish (PR #51).
func canonicalPublicationPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("config file path is empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err == nil {
		return resolved, nil
	}
	if !os.IsNotExist(err) {
		return "", err
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(absolute)), nil
}

func withConfigPublicationLock(path string, fn func(string) error) error {
	path, err := canonicalPublicationPath(path)
	if err != nil {
		return err
	}
	gate, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := gate.Close(); errClose != nil {
			log.WithError(errClose).Error("close config lock")
		}
	}()
	if err = lockConfigPublication(gate); err != nil {
		return err
	}
	defer func() {
		if errUnlock := unlockConfigPublication(gate); errUnlock != nil {
			log.WithError(errUnlock).Error("release config lock")
		}
	}()
	return fn(path)
}

func publishConfigLocked(path string, data []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return err
	}
	// Failed owner-private staging files are retained; never fall back to truncation.
	defer func() {
		if file != nil {
			if errClose := file.Close(); errClose != nil {
				log.WithError(errClose).Error("close config staging file")
			}
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	err = file.Close()
	name := file.Name()
	file = nil
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("atomic config publication refused; use a writable config directory (not a single-file bind mount): %w", err)
	}
	return syncConfigPublicationDir(dir)
}
