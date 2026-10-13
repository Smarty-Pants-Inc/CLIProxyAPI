package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// F32: a small zstd body that expands far past 16 MiB must not be fully decoded by request
// logging, with full logging on or off, and the handler must still get the original bytes.
func TestF32RequestLoggingZstdBombIsBounded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const decodedSize = 256 << 20
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for i := 0; i < decodedSize/len(chunk); i++ {
		if _, err = encoder.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err = encoder.Close(); err != nil {
		t.Fatal(err)
	}
	bomb := compressed.Bytes()
	if int64(len(bomb)) > maxErrorOnlyCapturedRequestBodyBytes {
		t.Fatalf("bomb is %d bytes, want <= 1 MiB so error-only capture applies", len(bomb))
	}

	for _, tc := range []struct {
		name     string
		enabled  bool
		maxAlloc uint64
	}{
		{"logging on", true, 96 << 20},
		{"logging off", false, 16 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.NewFileRequestLogger(tc.enabled, t.TempDir(), "", 10)
			router := gin.New()
			router.Use(RequestLoggingMiddleware(logger))
			router.POST("/v1/responses", func(c *gin.Context) {
				got, errRead := io.ReadAll(c.Request.Body)
				if errRead != nil || !bytes.Equal(got, bomb) {
					c.Status(http.StatusInternalServerError)
					return
				}
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(bomb))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Content-Encoding", "zstd")
			rec := httptest.NewRecorder()

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			router.ServeHTTP(rec, req)
			runtime.ReadMemStats(&after)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204 (handler must get the original body)", rec.Code)
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > tc.maxAlloc {
				t.Fatalf("request logging allocated %d MiB for a %d MiB zstd expansion, want <= %d MiB",
					alloc>>20, decodedSize>>20, tc.maxAlloc>>20)
			}
		})
	}
}
