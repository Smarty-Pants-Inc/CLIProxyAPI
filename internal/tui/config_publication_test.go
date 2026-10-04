package tui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestConfigYAMLClientPublishesWithSourceVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, nil)
	engine := gin.New()
	engine.GET("/v0/management/config.yaml", h.GetConfigYAML)
	engine.PUT("/v0/management/config.yaml", h.PutConfigYAML)
	server := httptest.NewServer(engine)
	defer server.Close()
	client := &Client{baseURL: server.URL, http: server.Client()}
	_, version, err := client.GetConfigYAMLWithVersion()
	if err != nil {
		t.Fatal(err)
	}
	if err = client.PutConfigYAML("debug: true\n"); err == nil {
		t.Fatal("client allowed a replacement without its source version")
	}
	if err = client.PutConfigYAML("debug: true\n", version); err != nil {
		t.Fatal(err)
	}
	if err = client.PutConfigYAML("debug: false\n", version); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("stale client write error = %v", err)
	}
	disk, err := config.LoadConfig(path)
	if err != nil || !disk.Debug {
		t.Fatalf("client lost a write: cfg=%+v err=%v", disk, err)
	}
}
