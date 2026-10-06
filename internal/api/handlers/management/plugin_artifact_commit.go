package management

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginstore"
)

func inspectPluginArtifact(staged, stagingDir, pluginsDir, id string, host *pluginhost.Host) (string, bool, bool, error) {
	rel, err := filepath.Rel(stagingDir, staged)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false, false, fmt.Errorf("invalid staged plugin path")
	}
	target := filepath.Join(pluginsDir, rel)
	candidate, err := os.ReadFile(staged)
	if err != nil {
		return target, false, false, err
	}
	existing, err := os.ReadFile(target)
	overwritten := err == nil
	if err != nil && !os.IsNotExist(err) {
		return target, false, false, err
	}
	identical := overwritten && bytes.Equal(existing, candidate)
	if overwritten && !identical && pluginBusy(host, id) {
		return target, true, false, pluginstore.ErrLoadedPluginLocked
	}
	return target, overwritten, identical, nil
}

// A downloaded artifact stays outside the scanner's platform directories until
// config commit. The publication lock remains held while this local effect runs.
func commitPluginArtifact(staged, stagingDir, pluginsDir, id string, host *pluginhost.Host) (string, bool, error) {
	target, overwritten, identical, err := inspectPluginArtifact(staged, stagingDir, pluginsDir, id, host)
	if err != nil || identical {
		return target, overwritten, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return target, overwritten, err
	}
	if err := os.Rename(staged, target); err != nil {
		return target, overwritten, fmt.Errorf("publish committed plugin artifact: %w", err)
	}
	return target, overwritten, nil
}
