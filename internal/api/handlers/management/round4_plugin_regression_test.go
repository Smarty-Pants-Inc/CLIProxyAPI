package management

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestRound4RejectedPluginInstallHasNoSideEffects(t *testing.T) {
	for _, reason := range []string{"stale", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			dir := t.TempDir()
			archive := makeManagementPluginStoreZip(t, "sample-provider"+managementPluginExtension(runtime.GOOS), "candidate-library")
			checksum := sha256.Sum256(archive)
			url := "https://downloads.example/sample.zip"
			configPath := writeTestConfigFile(t)
			h := &Handler{cfg: &config.Config{Plugins: config.PluginsConfig{Dir: dir}}, configFilePath: configPath, configVersion: testConfigSourceVersion("{}\n"), pluginStoreRegistryURL: "https://registry.example/registry.json", pluginStoreHTTPClient: fakePluginStoreHTTPClient{"https://registry.example/registry.json": directRegistryJSON(url, hex.EncodeToString(checksum[:])), url: archive}}
			target := filepath.Join(dir, runtime.GOOS, runtime.GOARCH, "sample-provider-v0.4.0"+managementPluginExtension(runtime.GOOS))
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("original-library"), 0600); err != nil {
				t.Fatal(err)
			}
			artifactInfo, _ := os.Stat(target)
			if reason == "stale" {
				if _, err := config.AtomicWriteConfigCAS(configPath, []byte("debug: true\n"), h.configVersion); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(configPath)
			beforeInfo, _ := os.Stat(configPath)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if reason == "cancelled" {
				cancel()
			}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Params = gin.Params{{Key: "id", Value: "sample-provider"}}
			c.Request = httptest.NewRequest(http.MethodPost, "/v0/management/plugin-store/sample-provider/install", nil).WithContext(ctx)
			h.InstallPluginFromStore(c)
			if rec.Code == http.StatusOK {
				t.Fatal("rejected install returned success")
			}
			raw, err := os.ReadFile(target)
			afterInfo, _ := os.Stat(target)
			if err != nil || string(raw) != "original-library" || !os.SameFile(artifactInfo, afterInfo) {
				t.Errorf("%s install changed artifact before CAS commit: %v", reason, err)
			}
			after, _ := os.ReadFile(configPath)
			afterConfigInfo, _ := os.Stat(configPath)
			if string(before) != string(after) || !os.SameFile(beforeInfo, afterConfigInfo) {
				t.Error("rejected install changed config")
			}
			if len(h.cfg.Plugins.Configs) != 0 {
				t.Error("rejected install changed runtime snapshot")
			}
			staged, _ := filepath.Glob(filepath.Join(dir, ".plugin-install-*"))
			if len(staged) != 0 {
				t.Fatal("rejected install retained staging")
			}
		})
	}
}

func TestRound4RejectedPluginDeleteHasNoSideEffects(t *testing.T) {
	for _, reason := range []string{"stale", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			dir := writeManagementPluginFile(t, "sample")
			artifact, err := pluginFilePath(dir, "sample")
			if err != nil {
				t.Fatal(err)
			}
			originalArtifact, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			artifactInfo, _ := os.Stat(artifact)
			path := filepath.Join(t.TempDir(), "config.yaml")
			source := []byte("plugins:\n  configs:\n    sample:\n      enabled: true\n")
			if err := os.WriteFile(path, source, 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Plugins.Dir = dir
			h := &Handler{cfg: cfg, configFilePath: path, configVersion: cfg.ConfigFileVersion}
			if reason == "stale" {
				if _, err := config.AtomicWriteConfigCAS(path, append(append([]byte(nil), source...), []byte("debug: true\n")...), cfg.ConfigFileVersion); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			info, _ := os.Stat(path)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if reason == "cancelled" {
				cancel()
			}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Params = gin.Params{{Key: "id", Value: "sample"}}
			c.Request = httptest.NewRequest(http.MethodDelete, "/v0/management/plugins/sample", nil).WithContext(ctx)
			h.DeletePlugin(c)
			if rec.Code == 200 {
				t.Fatal("rejected transaction returned success")
			}
			after, _ := os.ReadFile(path)
			newInfo, _ := os.Stat(path)
			data, err := os.ReadFile(artifact)
			newArtifactInfo, _ := os.Stat(artifact)
			if err != nil || string(data) != string(originalArtifact) || !os.SameFile(artifactInfo, newArtifactInfo) {
				t.Errorf("%s deletion changed plugin artifact before commit: %v", reason, err)
			}
			if string(before) != string(after) || !os.SameFile(info, newInfo) {
				t.Error("rejected transaction changed config")
			}
			if _, ok := h.cfg.Plugins.Configs["sample"]; !ok {
				t.Error("rejected transaction changed handler plugin state")
			}
		})
	}
}
