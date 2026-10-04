package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// LoadConfig reads a YAML configuration file using the complete server parser.
// Plaintext management keys are hashed and persisted under the publication lock.
func LoadConfig(configFile string) (*Config, error) {
	return LoadConfigOptional(configFile, false)
}

// LoadConfigOptional returns an empty config for an optional missing or empty file.
func LoadConfigOptional(configFile string, optional bool) (*Config, error) {
	return loadConfigOptional(configFile, optional, false)
}

func loadConfigOptional(configFile string, optional, locked bool) (*Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if optional && (os.IsNotExist(err) || errors.Is(err, syscall.EISDIR)) {
			cfg := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
			cfg.NormalizePluginsConfig()
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if optional && len(bytes.TrimSpace(data)) == 0 {
		cfg := &Config{CredentialInFlight: DefaultCredentialInFlightConfig()}
		cfg.NormalizePluginsConfig()
		return cfg, nil
	}
	// Operators and server startup share exactly this validation/normalization.
	cfg, errParse := parseConfigBytes(data, false)
	if errParse != nil {
		return nil, errParse
	}
	if cfg.RemoteManagement.SecretKey != "" && !looksLikeBcrypt(cfg.RemoteManagement.SecretKey) {
		if !locked {
			var current *Config
			errLock := withConfigFileLock(configFile, func(configFile string) error {
				var errLoad error
				current, errLoad = loadConfigOptional(configFile, optional, true)
				return errLoad
			})
			return current, errLock
		}
		hashed, errHash := hashSecret(cfg.RemoteManagement.SecretKey)
		if errHash != nil {
			return nil, fmt.Errorf("failed to hash remote management key: %w", errHash)
		}
		cfg.RemoteManagement.SecretKey = hashed
		if errSave := saveConfigPreserveCommentsUpdateNestedScalarUnlocked(configFile, []string{"remote-management", "secret-key"}, hashed); errSave != nil {
			return nil, fmt.Errorf("failed to publish hashed management key: %w", errSave)
		}
		published, errPublished := os.ReadFile(configFile)
		if errPublished != nil {
			return nil, fmt.Errorf("failed to read published config: %w", errPublished)
		}
		cfg.ConfigFileVersion = configVersion(published)
	}
	return cfg, nil
}
