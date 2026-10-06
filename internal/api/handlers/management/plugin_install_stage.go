package management

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginstore"
)

// commitStagedPlugin is called with Handler.mu held after validating the install
// lease. The downloaded file lives on the same filesystem as its final target.
func commitStagedPlugin(result *pluginstore.InstallResult, pluginsDir, goos, goarch string, pluginBusy func() bool) error {
	target := filepath.Join(pluginsDir, goos, goarch, filepath.Base(result.Path))
	result.Overwritten = false
	result.Skipped = false
	if _, errStat := os.Stat(target); errStat == nil {
		result.Overwritten = true
		existing, errExisting := os.ReadFile(target)
		if errExisting != nil {
			return fmt.Errorf("read target plugin: %w", errExisting)
		}
		staged, errStaged := os.ReadFile(result.Path)
		if errStaged != nil {
			return fmt.Errorf("read staged plugin: %w", errStaged)
		}
		if bytes.Equal(existing, staged) {
			result.Path = target
			result.Skipped = true
			return nil
		}
		if strings.EqualFold(goos, "windows") && pluginBusy() {
			return pluginstore.ErrLoadedPluginLocked
		}
	} else if !errors.Is(errStat, os.ErrNotExist) {
		return fmt.Errorf("stat target plugin: %w", errStat)
	}
	if errMkdir := os.MkdirAll(filepath.Dir(target), 0o755); errMkdir != nil {
		return fmt.Errorf("create plugin directory: %w", errMkdir)
	}
	if errRename := os.Rename(result.Path, target); errRename != nil {
		if runtime.GOOS != "windows" {
			return fmt.Errorf("install plugin file: %w", errRename)
		}
		if errRemove := os.Remove(target); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			return fmt.Errorf("remove old plugin file: %w", errRemove)
		}
		if errRetry := os.Rename(result.Path, target); errRetry != nil {
			return fmt.Errorf("install plugin file: %w", errRetry)
		}
	}
	result.Path = target
	return nil
}
