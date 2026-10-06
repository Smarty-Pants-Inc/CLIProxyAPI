package management

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestDeletePluginFreezePreservesFileAfterAdmission(t *testing.T) {
	for _, writer := range []string{"deferred disk policies", "v8 config policies"} {
		t.Run(writer, func(t *testing.T) {
			pluginsDir := writeManagementPluginFile(t, "sample")
			pluginPath, err := pluginFilePath(pluginsDir, "sample")
			if err != nil || pluginPath == "" {
				t.Fatalf("plugin discovery: path=%q err=%v", pluginPath, err)
			}
			originalFile, err := os.ReadFile(pluginPath)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			initial := fmt.Sprintf("port: 8317\napi-keys: [K]\nplugins:\n  dir: %q\n  configs:\n    sample:\n      enabled: false\n", pluginsDir)
			if err := os.WriteFile(configPath, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg.RemoteManagement.AllowRemote = true
			h := &Handler{cfg: cfg, configFilePath: configPath, envSecret: "pw", failedAttempts: map[string]*attemptInfo{}}
			admitted, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			router := gin.New()
			group := router.Group("/v8/management")
			group.Use(h.Middleware(), func(c *gin.Context) {
				c.Set(ConfigV8ContextKey, true)
				if c.Request.Method == http.MethodDelete {
					// The deletion passed admission before a config writer installs policies.
					close(admitted)
					<-resume
				}
				c.Next()
			})
			group.DELETE("/plugins/:id", h.DeletePlugin)
			group.PATCH("/config", h.ConfigV8)
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/v8/management/plugins/sample", nil)
			req.Header.Set("Authorization", "Bearer pw")
			go func() {
				defer close(done)
				router.ServeHTTP(rec, req)
			}()
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
				<-done
			}()
			select {
			case <-admitted:
			case <-time.After(5 * time.Second):
				t.Fatal("deletion did not reach the post-admission barrier")
			}

			digest := config.APIKeyDigest("K")
			if writer == "deferred disk policies" {
				desired := initial + "api-key-policies:\n  - key-sha256: " + digest + "\n"
				if err := os.WriteFile(configPath, []byte(desired), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				writeRec := httptest.NewRecorder()
				body := `{"access":{"api-key-policies":[{"key-sha256":"` + digest + `"}]}}`
				writeReq := httptest.NewRequest(http.MethodPatch, "/v8/management/config", strings.NewReader(body))
				writeReq.Header.Set("Authorization", "Bearer pw")
				router.ServeHTTP(writeRec, writeReq)
				if writeRec.Code != http.StatusOK {
					t.Fatalf("policy config write: status=%d body=%s", writeRec.Code, writeRec.Body.String())
				}
			}
			desiredDisk, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			runtimeConfig := h.cfg
			close(resume)
			<-done

			disk, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			file, errReadFile := os.ReadFile(pluginPath)
			_, configured := h.cfg.Plugins.Configs["sample"]
			t.Logf("status=%d file_intact=%t config_intact=%t disk_unchanged=%t body=%s", rec.Code, errReadFile == nil && bytes.Equal(file, originalFile), configured, bytes.Equal(disk, desiredDisk), rec.Body.String())
			if rec.Code != http.StatusConflict || rec.Body.String() != `{"error":"`+errPolicyConfigFrozen+`"}` {
				t.Fatalf("delete refusal: status=%d body=%s", rec.Code, rec.Body.String())
			}
			if !bytes.Equal(disk, desiredDisk) || h.cfg != runtimeConfig || !configured {
				t.Fatal("refused deletion changed disk or runtime plugin configuration")
			}
			if errReadFile != nil || !bytes.Equal(file, originalFile) {
				t.Fatalf("refused deletion removed or changed plugin file: %v", errReadFile)
			}
		})
	}
}
