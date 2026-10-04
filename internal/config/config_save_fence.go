package config

import (
	"crypto/sha256"
	"errors"
	"os"
	"sync"
)

// ErrStaleConfig means a full save has no source revision or the file no longer
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

// Serialize this package's file saves, not all management mutations or external
// writers. This mutex is not a cross-process transaction boundary.
var configSaveMu sync.Mutex

// writeConfigRevision validates before truncating. An uncooperative external
// writer can still race between this check and publication; see the scope doc.
// Callers hold configSaveMu and advance metadata only after successful writing.
func writeConfigRevision(path string, data []byte, expected configSourceRevision) error {
	current, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ErrStaleConfig
	}
	if err != nil {
		return err
	}
	if !expected.matches(current) {
		return ErrStaleConfig
	}
	return os.WriteFile(path, data, 0600)
}
