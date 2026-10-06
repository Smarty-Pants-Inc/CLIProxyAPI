package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestManagementKeyStartupAndSavePublication(t *testing.T) {
	dir, err := os.MkdirTemp("", "config-key-publication-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	const secret = "unit-test-only-management-key"
	source := "# preserved\nremote-management:\n  secret-key: " + secret + "\nrequest-retry: 2\n"
	if err = AtomicWriteConfig(path, []byte(source)); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = bcrypt.CompareHashAndPassword([]byte(cfg.RemoteManagement.SecretKey), []byte(secret)); err != nil {
		t.Fatalf("startup hash: %v", err)
	}
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(published), secret) || !strings.Contains(string(published), cfg.RemoteManagement.SecretKey) {
		t.Fatal("startup did not persist the hash")
	}
	cfg.RequestRetry = 9
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RequestRetry != 9 || reloaded.RemoteManagement.SecretKey != cfg.RemoteManagement.SecretKey {
		t.Fatal("save lost matching config/key snapshot")
	}
	published, err = os.ReadFile(path)
	if err != nil || !strings.Contains(string(published), "# preserved") || strings.Contains(string(published), secret) {
		t.Fatalf("save did not preserve comments/hash: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, errStat := os.Stat(path)
		if errStat != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("startup/save privacy: %v %v", info, errStat)
		}
	}
}
