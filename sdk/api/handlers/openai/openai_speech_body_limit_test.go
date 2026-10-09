package openai

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
)

// countingBody yields up to size bytes of a JSON-ish payload and records how
// many bytes the handler actually pulled from the wire.
type countingBody struct {
	remaining int64
	read      int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > b.remaining {
		n = b.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = ' '
	}
	b.remaining -= n
	b.read += n
	return int(n), nil
}

func (b *countingBody) Close() error { return nil }

func serveSpeech(t *testing.T, handler gin.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/v1/audio/speech", handler)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func TestSpeechBodyLimitRejectsOversizedBeforeBuffering(t *testing.T) {
	executor := &speechCaptureExecutor{}
	handler, _ := newSpeechRoutingTestHandlers(t, executor)

	for _, tc := range []struct {
		name          string
		contentLength int64
	}{
		{name: "plain", contentLength: 64 << 20},
		{name: "chunked", contentLength: -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &countingBody{remaining: 64 << 20}
			req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", nil)
			req.Body = body
			req.ContentLength = tc.contentLength
			if tc.contentLength < 0 {
				req.TransferEncoding = []string{"chunked"}
			}
			req.Header.Set("Content-Type", "application/json")

			resp := serveSpeech(t, handler.AudioSpeech, req)
			if resp.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413: %s", resp.Code, resp.Body.String())
			}
			if body.read > maxXAISpeechBody+1 {
				t.Fatalf("handler read %d bytes, want <= %d", body.read, maxXAISpeechBody+1)
			}
		})
	}
	if models, _ := executor.calls(); len(models) != 0 {
		t.Fatalf("executor called for oversized body: %v", models)
	}
}

func TestSpeechBodyLimitRejectsOversizedDecodedZstd(t *testing.T) {
	executor := &speechCaptureExecutor{}
	handler, _ := newSpeechRoutingTestHandlers(t, executor)

	// Small on the wire, 8 MiB once decoded.
	plain := []byte(`{"model":"tts-1","voice":"nova","input":"` + strings.Repeat("a", 8<<20) + `"}`)
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := encoder.EncodeAll(plain, nil)
	_ = encoder.Close()
	if len(compressed) >= maxXAISpeechBody {
		t.Fatalf("compressed body unexpectedly large: %d", len(compressed))
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(compressed))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "zstd")
	resp := serveSpeech(t, handler.AudioSpeech, req)
	if resp.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413: %s", resp.Code, resp.Body.String())
	}
	if models, _ := executor.calls(); len(models) != 0 {
		t.Fatalf("executor called for oversized decoded body: %v", models)
	}
}

func TestSpeechBodyLimitAcceptsNormalBodies(t *testing.T) {
	executor := &speechCaptureExecutor{}
	handler, _ := newSpeechRoutingTestHandlers(t, executor)
	plain := []byte(`{"model":"tts-1","input":"hello","voice":"nova"}`)

	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	compressed := encoder.EncodeAll(plain, nil)
	_ = encoder.Close()

	for _, tc := range []struct {
		name     string
		body     []byte
		encoding string
	}{
		{name: "plain", body: plain},
		{name: "zstd", body: compressed, encoding: "zstd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			resp := serveSpeech(t, handler.AudioSpeech, req)
			if resp.Code != http.StatusOK || resp.Body.String() != "ID3audio" {
				t.Fatalf("status = %d body = %q, want 200 ID3audio", resp.Code, resp.Body.String())
			}
		})
	}
}
