package handlers

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
)

// Keep reason: both the fork's endpoint cap and upstream's configurable cap
// must reach the shared client-error mapping, including decompression failures.
func TestReadRequestBodyLimitCombinesCapsAndHTTPStatus(t *testing.T) {
	plain := []byte(strings.Repeat("x", 4096))
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(plain, nil)
	encoder.Close()
	for _, tc := range []struct {
		name             string
		body             []byte
		encoding         string
		global, endpoint int64
		tooLarge         bool
	}{
		{"global-wire", plain, "", 128, 0, true},
		{"endpoint-wire", plain, "", 0, 128, true},
		{"global-tighter", compressed, "zstd", 128, 8192, true},
		{"endpoint-tighter", compressed, "zstd", 8192, 128, true},
		{"normal", []byte(`{"input":"ok"}`), "", 128, 64, false},
		{"unlimited", plain, "", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(tc.body))
			c.Request.Header.Set("Content-Encoding", tc.encoding)
			c.Set(MaxRequestBodyBytesContextKey, tc.global)
			got, errRead := ReadRequestBodyLimit(c, tc.endpoint)
			if tc.tooLarge {
				if !errors.Is(errRead, ErrRequestBodyTooLarge) || clienterror.HTTPStatusFromError(errRead) != http.StatusRequestEntityTooLarge {
					t.Fatalf("want both fork sentinel and upstream HTTP 413 classification, got %v", errRead)
				}
			} else if errRead != nil || !bytes.Equal(got, tc.body) {
				t.Fatalf("ordinary request: got %q, %v", got, errRead)
			}
		})
	}
}
