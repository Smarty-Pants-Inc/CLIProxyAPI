package logging_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/middleware"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

type fakeRequestLogQueue struct{ pushed [][]byte }

func (*fakeRequestLogQueue) HeartbeatOK() bool { return true }
func (q *fakeRequestLogQueue) RPushRequestLog(_ context.Context, data []byte) error {
	q.pushed = append(q.pushed, append([]byte(nil), data...))
	return nil
}

// Keep: data safety across the hot-disable/merge-failure -> Home queue boundary.
func TestFinalizeCleansStreamingSpoolsAfterDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, failure := range []string{"disabled", "source_error"} {
		t.Run(failure, func(t *testing.T) {
			queue := &fakeRequestLogQueue{}
			logging.WithHomeRequestLogClientForTest(queue, func() {
				dir := t.TempDir()
				logger := logging.NewFileRequestLogger(true, dir, "", 10)
				logger.SetHomeEnabled(true)
				// Positive control proves this queue is healthy and the real home writer is active.
				control, err := logger.LogStreamingRequest("/v1/responses", http.MethodPost, nil, []byte("synthetic control"), "control")
				if err != nil {
					t.Fatal(err)
				}
				control.WriteChunkAsync([]byte("data: control\n\n"))
				if err := control.Close(); err != nil {
					t.Fatal(err)
				}
				if len(queue.pushed) != 1 || !strings.Contains(string(queue.pushed[0]), "synthetic control") {
					t.Fatal("home positive control did not push a real log")
				}
				queue.pushed = nil
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
				if _, err := io.WriteString(part, "synthetic upstream"); err != nil {
					t.Fatal(err)
				}
				if err := part.Close(); err != nil {
					t.Fatal(err)
				}
				c.Set(logging.APIWebsocketTimelineSourceContextKey, source)
				wrapper := middleware.NewResponseWriterWrapper(c.Writer, logger, &middleware.RequestInfo{URL: "/v1/responses", Method: http.MethodPost, Body: []byte("synthetic prompt")})
				wrapper.Header().Set("Content-Type", "text/event-stream")
				wrapper.WriteHeader(http.StatusOK)
				if _, err := io.WriteString(wrapper, "data: synthetic\n\n"); err != nil {
					t.Fatal(err)
				}
				if failure == "disabled" {
					logger.SetEnabled(false)
				} else {
					if err := os.Remove(part.Name()); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(part.Name(), 0700); err != nil {
						t.Fatal(err)
					}
				}
				err = wrapper.Finalize(c)
				if (err != nil) != (failure == "source_error") {
					t.Fatalf("Finalize = %v for %s", err, failure)
				}
				if len(queue.pushed) != 0 {
					t.Fatalf("discarded stream pushed %d home logs", len(queue.pushed))
				}
				if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if strings.HasSuffix(entry.Name(), ".log") || strings.HasSuffix(entry.Name(), ".tmp") || strings.HasPrefix(entry.Name(), "request-log-parts-") {
						t.Errorf("discarded stream left file %s", path)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
