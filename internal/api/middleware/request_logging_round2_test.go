package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// Keep: data safety at the real Gin recovery/request-logging boundary (PR #178).
func TestRequestLoggingRecoveryStackCleansSpoolsOnAbort(t *testing.T) {
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	logger := logging.NewFileRequestLogger(true, dir, "", 10)
	router := gin.New()
	router.Use(logging.GinLogrusRecovery(), RequestLoggingMiddleware(logger))
	router.POST("/v1/responses", func(c *gin.Context) {
		for _, key := range []string{logging.APIRequestSourceContextKey, logging.APIResponseSourceContextKey} {
			source := extractFileBodySource(c, key)
			if source == nil {
				t.Fatalf("missing source %s", key)
			}
			if err := source.AppendPart([]byte("synthetic upstream detail")); err != nil {
				t.Fatal(err)
			}
		}
		c.Header("Content-Type", "text/event-stream")
		if _, err := io.WriteString(c.Writer, "data: synthetic\n\n"); err != nil {
			t.Fatal(err)
		}
		c.Writer.Flush()
		panic(http.ErrAbortHandler)
	})
	recorder := httptest.NewRecorder()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader("synthetic prompt")))
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("panic = %v, want ErrAbortHandler", recovered)
	}
	if !strings.Contains(recorder.Body.String(), "data: synthetic") {
		t.Fatal("stream did not emit a chunk before aborting")
	}
	assertNoRequestLogSpools(t, dir)
}

// Keep: data safety when net/http cleanup/finalization overlaps a body reader.
// Run with -race: the same capture state is read, finished and removed concurrently.
func TestDeferredRequestBodyCaptureConcurrentCleanup(t *testing.T) {
	dir := t.TempDir()
	logger := logging.NewFileRequestLogger(false, dir, "", 10)
	for i := 0; i < 64; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", io.NopCloser(strings.NewReader(strings.Repeat("synthetic", 512))))
		info := &RequestInfo{}
		capture := attachDeferredRequestBodyCapture(req, logger, info, false, false)
		if capture == nil {
			t.Fatal("capture was not attached")
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			buf := make([]byte, 17)
			for j := 0; j < 256; j++ {
				_, _ = capture.Read(buf)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 32; j++ {
				_, _, _ = capture.Bytes()
				_ = capture.statusMarker()
				_ = capture.Finish()
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			capture.Cleanup()
		}()
		close(start)
		wg.Wait()
		if err := capture.Close(); err != nil {
			t.Fatal(err)
		}
		capture.Cleanup()
	}
	assertNoRequestLogSpools(t, dir)
}
