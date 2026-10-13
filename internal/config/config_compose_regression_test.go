package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestComposeUsesRenameCapableConfigDirectory(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	compose := string(data)
	if !strings.Contains(compose, "${CLI_PROXY_CONFIG_DIR:-./config}:/CLIProxyAPI/config") {
		t.Fatal("Compose must mount a config directory")
	}
	if !strings.Contains(compose, "--config") || !strings.Contains(compose, "/CLIProxyAPI/config/config.yaml") {
		t.Fatal("Compose must select the config file inside the directory mount")
	}
	if strings.Contains(compose, "CLI_PROXY_CONFIG_PATH") {
		t.Fatal("Compose must not use a single-file config bind mount")
	}
}
