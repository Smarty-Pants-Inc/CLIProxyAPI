// config_reload.go implements debounced configuration hot reload.
// It detects material changes and reloads clients when the config changes.
package watcher

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"reflect"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/diff"
	"gopkg.in/yaml.v3"

	log "github.com/sirupsen/logrus"
)

func (w *Watcher) stopConfigReloadTimer() {
	w.configReloadMu.Lock()
	if w.configReloadTimer != nil {
		w.configReloadTimer.Stop()
		w.configReloadTimer = nil
	}
	w.configReloadMu.Unlock()
}

func (w *Watcher) scheduleConfigReload() {
	w.configReloadMu.Lock()
	defer w.configReloadMu.Unlock()
	if w.configReloadTimer != nil {
		w.configReloadTimer.Stop()
	}
	w.configReloadTimer = time.AfterFunc(configReloadDebounce, func() {
		w.configReloadMu.Lock()
		w.configReloadTimer = nil
		w.configReloadMu.Unlock()
		w.reloadConfigIfChanged()
	})
}

// ReloadConfigIfChanged runs the same config reload path used by filesystem events.
func (w *Watcher) ReloadConfigIfChanged() {
	if w == nil {
		return
	}
	w.reloadConfigIfChanged()
}

func (w *Watcher) reloadConfigIfChanged() {
	w.reloadConfigIfChangedWithRead(os.ReadFile)
}

// A per-call read seam allows deterministic observation/publication tests.
func (w *Watcher) reloadConfigIfChangedWithRead(read func(string) ([]byte, error)) {
	w.configApplyMu.Lock()
	defer w.configApplyMu.Unlock()
	data, err := read(w.configPath)
	if err != nil {
		log.Errorf("failed to read config file for hash check: %v", err)
		return
	}
	if len(data) == 0 {
		log.Debugf("ignoring empty config file write event")
		return
	}
	sum := sha256.Sum256(data)
	newHash := hex.EncodeToString(sum[:])

	w.clientsMutex.RLock()
	currentHash := w.lastConfigHash
	w.clientsMutex.RUnlock()

	if currentHash != "" && currentHash == newHash {
		log.Debugf("config file content unchanged (hash match), skipping reload")
		return
	}
	log.Infof("config file changed, reloading: %s", w.configPath)
	// Once apply begins, a prior observation may no longer describe runtime.
	// Clear it first so a concurrent revert cannot be skipped after apply.
	w.clientsMutex.Lock()
	w.lastConfigHash = ""
	w.clientsMutex.Unlock()
	if w.reloadConfig(data) {
		// A publication during apply invalidates this observation. Leave the
		// revision unrecorded so the newer event is retried.
		current, errCurrent := read(w.configPath)
		if errCurrent != nil || !bytes.Equal(current, data) {
			log.Debug("config changed during reload; leaving revision unrecorded")
			return
		}
		// Close the final read/record gap under the same stable lock as
		// cooperating writers. Never assign the hash of a later disk reread.
		errRecord := config.RecordConfigObservation(w.configPath, data, func() {
			w.clientsMutex.Lock()
			w.lastConfigHash = newHash
			w.clientsMutex.Unlock()
		})
		if errRecord != nil {
			log.Debug("config observation invalidated; leaving revision unrecorded")
			return
		}
		w.persistConfigAsync()
	}
}

func (w *Watcher) reloadConfig(snapshots ...[]byte) bool {
	log.Debug("=========================== CONFIG RELOAD ============================")
	log.Debugf("starting config reload from: %s", w.configPath)

	var newConfig *config.Config
	var errLoadConfig error
	if len(snapshots) > 0 {
		newConfig, errLoadConfig = config.LoadConfigBytes(snapshots[0], w.configPath, false)
	} else {
		newConfig, errLoadConfig = config.LoadConfig(w.configPath)
	}
	if errLoadConfig != nil {
		log.Errorf("failed to reload config: %v", errLoadConfig)
		return false
	}

	if w.mirroredAuthDir != "" {
		newConfig.AuthDir = w.mirroredAuthDir
	} else {
		if resolvedAuthDir, errResolveAuthDir := util.ResolveAuthDir(newConfig.AuthDir); errResolveAuthDir != nil {
			log.Errorf("failed to resolve auth directory from config: %v", errResolveAuthDir)
		} else {
			newConfig.AuthDir = resolvedAuthDir
		}
	}

	w.clientsMutex.Lock()
	var oldConfig *config.Config
	_ = yaml.Unmarshal(w.oldConfigYaml, &oldConfig)
	w.config = newConfig
	w.clientsMutex.Unlock()

	var affectedOAuthProviders []string
	if oldConfig != nil {
		_, affectedOAuthProviders = diff.DiffOAuthExcludedModelChanges(oldConfig.OAuthExcludedModels, newConfig.OAuthExcludedModels)
	}

	util.SetLogLevel(newConfig)
	if oldConfig != nil && oldConfig.Debug != newConfig.Debug {
		log.Debugf("log level updated - debug mode changed from %t to %t", oldConfig.Debug, newConfig.Debug)
	}

	if oldConfig != nil {
		details := diff.BuildConfigChangeDetails(oldConfig, newConfig)
		if len(details) > 0 {
			log.Info("config changes detected:")
			for _, d := range details {
				log.Infof("  %s", d)
			}
		} else {
			log.Debugf("no material config field changes detected")
		}
	}

	authDirChanged := oldConfig == nil || oldConfig.AuthDir != newConfig.AuthDir
	retryConfigChanged := oldConfig != nil && (oldConfig.RequestRetry != newConfig.RequestRetry || oldConfig.MaxRetryInterval != newConfig.MaxRetryInterval || oldConfig.MaxRetryCredentials != newConfig.MaxRetryCredentials)
	forceAuthRefresh := oldConfig != nil && (oldConfig.ForceModelPrefix != newConfig.ForceModelPrefix || !reflect.DeepEqual(oldConfig.OAuthModelAlias, newConfig.OAuthModelAlias) || retryConfigChanged)

	log.Infof("config successfully reloaded, triggering client reload")
	if !w.reloadClients(authDirChanged, affectedOAuthProviders, forceAuthRefresh) {
		return false
	}
	// Retain the prior applied snapshot on failure so retry preserves rescan
	// and auth-refresh decisions as well as leaving the hash unobserved.
	w.clientsMutex.Lock()
	w.oldConfigYaml, _ = yaml.Marshal(newConfig)
	w.clientsMutex.Unlock()
	return true
}
