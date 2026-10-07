package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestFullSaveFencePublicContract(t *testing.T) {
	if config.ErrStaleConfig != internalconfig.ErrStaleConfig {
		t.Fatal("SDK sentinel is not the internal sentinel")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	input := []byte("port: 8080\n")
	if err := os.WriteFile(path, input, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.ParseConfigBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	copy := *cfg
	cfg.Port = 8081
	if err = config.SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	if err = config.SaveConfigPreserveComments(path, &copy); !errors.Is(err, config.ErrStaleConfig) {
		t.Fatalf("copied snapshot error = %v", err)
	}
	if err = config.SaveConfigPreserveComments(path, &config.Config{}); !errors.Is(err, config.ErrStaleConfig) {
		t.Fatalf("untracked snapshot error = %v", err)
	}
}
