package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestComposeConfigDirectoryPublication(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	compose, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compose), "${CLI_PROXY_CONFIG_DIR:-./config}:/CLIProxyAPI/config") || !strings.Contains(string(compose), `command: ["--config", "/CLIProxyAPI/config/config.yaml"]`) {
		t.Fatal("Compose must mount a config directory and select the file inside it")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("remote-management:\n  secret-key: test-plaintext\nrequest-retry: 1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if !looksLikeBcrypt(cfg.RemoteManagement.SecretKey) {
		t.Fatal("plaintext not hashed")
	}
	for i := 2; i < 5; i++ {
		cfg.RequestRetry = i
		if err := SaveConfigPreserveComments(path, cfg); err != nil {
			t.Fatal(err)
		}
		cfg, err = LoadConfig(path)
		if err != nil || cfg.RequestRetry != i {
			t.Fatalf("publication %d: %v", i, err)
		}
	}
}
