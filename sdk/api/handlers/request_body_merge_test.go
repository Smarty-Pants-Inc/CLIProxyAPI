package handlers

import (
	"bytes"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
)

func TestReadRequestBodyMergeUsesStricterCapAndBothErrorContracts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, encoding := range []string{"identity", "zstd"} {
		for _, limits := range [][2]int64{{128, 0}, {128, 256}, {256, 128}} {
			body := bytes.Repeat([]byte("x"), 129)
			if encoding == "zstd" {
				encoder, err := zstd.NewWriter(nil)
				if err != nil {
					t.Fatal(err)
				}
				body = encoder.EncodeAll(body, nil)
				encoder.Close()
			}
			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			ctx.Request.Header.Set("Content-Encoding", encoding)
			ctx.Set(MaxRequestBodyBytesContextKey, limits[0])
			_, err := ReadRequestBodyLimit(ctx, limits[1])
			var maxErr *http.MaxBytesError
			if !errors.Is(err, ErrRequestBodyTooLarge) || !errors.As(err, &maxErr) || maxErr.Limit != 128 || clienterror.HTTPStatusFromErrorOr(err, 400) != 413 {
				t.Fatalf("encoding=%s limits=%v error=%v: want both fork and upstream 413 contracts", encoding, limits, err)
			}
		}
	}
}

func TestDecodeZstdRequestBodyMergeMaxInt64DoesNotOverflow(t *testing.T) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	want := []byte(`{"ok":true}`)
	got, err := decodeZstdRequestBody(encoder.EncodeAll(want, nil), math.MaxInt64)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("decode at MaxInt64 = %q, %v", got, err)
	}
}
