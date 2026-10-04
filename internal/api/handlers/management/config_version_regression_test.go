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

func TestSourceVersionCannotBeBorrowedFromNewerDisk(t *testing.T) {
	for _, setter := range []bool{false, true} {
		for _, parsed := range []bool{false, true} {
			t.Run(map[bool]string{false: "constructor", true: "SetConfig"}[setter]+map[bool]string{false: "/unversioned", true: "/parsed"}[parsed], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "config.yaml")
				original := []byte("request-retry: 1\n")
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				stale := &config.Config{RequestRetry: 1}
				var err error
				if parsed {
					stale, err = config.ParseConfigBytes(original)
					if err != nil {
						t.Fatal(err)
					}
				}
				version, err := config.ConfigFileVersion(path)
				if err != nil {
					t.Fatal(err)
				}
				newer := []byte("request-retry: 8\n")
				if _, err := config.AtomicWriteConfigCAS(path, newer, version); err != nil {
					t.Fatal(err)
				}
				var h *Handler
				if setter {
					current, err := config.LoadConfig(path)
					if err != nil {
						t.Fatal(err)
					}
					h = NewHandler(current, path, nil)
					h.SetConfig(stale)
				} else {
					h = NewHandler(stale, path, nil)
				}
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPut, "/v0/management/request-retry", bytes.NewBufferString(`{"value":2}`))
				h.PutRequestRetry(c)
				want := http.StatusInternalServerError
				if parsed {
					want = http.StatusConflict
				}
				if rec.Code != want {
					t.Fatalf("stale publication status=%d want=%d: %s", rec.Code, want, rec.Body.String())
				}
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, newer) {
					t.Fatalf("stale snapshot replaced newer bytes: %q %v", got, err)
				}
			})
		}
	}
}
