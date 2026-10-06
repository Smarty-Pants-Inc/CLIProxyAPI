package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// Finalize must drain the worker even when it runs before the newly launched
// goroutine reaches its channel range. Under -race, the old channel field reads
// race with Finalize clearing the field (and can range over a nil channel).
func TestFinalizeStreamingWorkerStartupRace(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for i := 0; i < 2000; i++ {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
		streamWriter := &startupRaceStreamingLogWriter{}
		logger := &startupRaceRequestLogger{
			testRequestLogger: testRequestLogger{enabled: true},
			streamWriter:      streamWriter,
		}
		wrapper := NewResponseWriterWrapper(c.Writer, logger, &RequestInfo{
			URL: "/v1/responses", Method: http.MethodPost, RequestID: "startup-race",
		})
		wrapper.Header().Set("Content-Type", "text/event-stream")
		wrapper.WriteHeader(http.StatusOK)
		done := wrapper.streamDone

		// Alternate empty streams and streams with queued chunks to cover both
		// immediate shutdown and draining a channel already closed by Finalize.
		var want string
		if i%2 == 0 {
			want = "data: one\n\ndata: two\n\n"
			if _, err := wrapper.Write([]byte("data: one\n\n")); err != nil {
				t.Fatalf("iteration %d Write: %v", i, err)
			}
			if _, err := wrapper.WriteString("data: two\n\n"); err != nil {
				t.Fatalf("iteration %d WriteString: %v", i, err)
			}
		}
		if err := wrapper.Finalize(c); err != nil {
			t.Fatalf("iteration %d Finalize: %v", i, err)
		}
		select {
		case <-done:
		default:
			t.Fatalf("iteration %d: Finalize returned before worker exited", i)
		}
		if got := streamWriter.chunks.String(); got != want {
			t.Fatalf("iteration %d chunks = %q, want %q", i, got, want)
		}
		if !streamWriter.closed {
			t.Fatalf("iteration %d: streaming log not closed", i)
		}
		if wrapper.chunkChannel != nil || wrapper.streamDone != nil {
			t.Fatalf("iteration %d: completed stream still owns channel state", i)
		}
	}
}

type startupRaceRequestLogger struct {
	testRequestLogger
	streamWriter *startupRaceStreamingLogWriter
}

func (l *startupRaceRequestLogger) LogStreamingRequest(string, string, map[string][]string, []byte, string) (logging.StreamingLogWriter, error) {
	return l.streamWriter, nil
}

type startupRaceStreamingLogWriter struct {
	testStreamingLogWriter
	chunks bytes.Buffer
}

func (w *startupRaceStreamingLogWriter) WriteChunkAsync(chunk []byte) {
	w.chunks.Write(chunk)
}
