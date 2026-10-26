package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// Keep: data safety on a finalization error that normal API flows cannot induce cheaply.
func TestFinalizeCleansStreamingSpoolsOnSourceError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logsDir := t.TempDir()
	logger := logging.NewFileRequestLogger(true, logsDir, "", 10)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	source, err := logger.NewFileBodySource("api-websocket-timeline")
	if err != nil {
		t.Fatal(err)
	}
	part, err := source.CreatePart("part")
	if err != nil {
		t.Fatal(err)
	}
	if err = part.Close(); err != nil {
		t.Fatal(err)
	}
	// A directory in place of a log part makes merging fail without a permission assumption.
	if err = os.Remove(part.Name()); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(part.Name(), 0700); err != nil {
		t.Fatal(err)
	}
	c.Set(logging.APIWebsocketTimelineSourceContextKey, source)
	wrapper := NewResponseWriterWrapper(c.Writer, logger, &RequestInfo{URL: "/v1/responses", Method: http.MethodPost, Body: []byte("synthetic")})
	wrapper.Header().Set("Content-Type", "text/event-stream")
	wrapper.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(wrapper, "data: synthetic\n\n")
	if err = wrapper.Finalize(c); err == nil {
		t.Fatal("expected source merge error")
	}
	assertNoRequestLogSpools(t, logsDir)
	logs, errGlob := filepath.Glob(filepath.Join(logsDir, "*.log"))
	if errGlob != nil || len(logs) != 0 {
		t.Fatalf("unexpected completed logs: %v, %v", logs, errGlob)
	}
	if wrapper.streamWriter != nil {
		t.Fatal("streaming writer was not released")
	}
}

// Keep: data safety across the supported request-log hot reload boundary.
func TestFinalizeCleansStreamingSpoolsAfterDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logsDir := t.TempDir()
	logger := logging.NewFileRequestLogger(true, logsDir, "", 10)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	wrapper := NewResponseWriterWrapper(c.Writer, logger, &RequestInfo{URL: "/v1/responses", Method: http.MethodPost, Body: []byte("synthetic")})
	wrapper.Header().Set("Content-Type", "text/event-stream")
	wrapper.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(wrapper, "data: synthetic\n\n")
	logger.SetEnabled(false)
	if err := wrapper.Finalize(c); err != nil {
		t.Fatal(err)
	}
	assertNoRequestLogSpools(t, logsDir)
	logs, errGlob := filepath.Glob(filepath.Join(logsDir, "*.log"))
	if errGlob != nil || len(logs) != 0 {
		t.Fatalf("unexpected completed logs: %v, %v", logs, errGlob)
	}
	if wrapper.streamWriter != nil {
		t.Fatal("streaming writer was not released after disabling request-log")
	}
}
