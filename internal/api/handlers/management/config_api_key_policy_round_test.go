package management

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestAPIKeyPolicyYAMLUploadRejectsHiddenDocuments(t *testing.T) {
	for _, key := range []string{`"\u0061pi-key-policies"`, "? \"api-key-\\\n  policies\"\n"} {
		t.Run(key, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			original := []byte("port: 8383\napi-keys: [synthetic]\n")
			if err := os.WriteFile(file, original, 0600); err != nil {
				t.Fatal(err)
			}
			h := &Handler{cfg: &config.Config{}, configFilePath: file}
			payload := append(append([]byte(nil), original...), []byte("---\n"+key+": [{key-sha256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad, allowed-auths: []}]\n")...)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPut, "/config.yaml", bytes.NewReader(payload))
			h.PutConfigYAML(c)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("hidden security document accepted: status=%d body=%s", w.Code, w.Body.String())
			}
			got, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, original) {
				t.Fatal("rejected upload changed live config")
			}
		})
	}
}
