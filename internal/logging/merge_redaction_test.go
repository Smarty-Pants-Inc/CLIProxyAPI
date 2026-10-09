package logging

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/httpwire"
	log "github.com/sirupsen/logrus"
)

func TestLogFormatterRedactsNewUpstreamAuthAndErrorFields(t *testing.T) {
	entry := log.NewEntry(log.New())
	entry.Message = "upstream connection failed"
	entry.Data["request_id"] = "018f3a5b-1234-7abc-def0-12345678abcd"
	entry.Data["auth_ref"] = "a1b2c3d4e5f6"
	entry.Data["auth_id"] = "private-auth-record"
	entry.Data["credential"] = "person@example.com"
	entry.Data["connection"] = "socks5://person:password@proxy.invalid"
	// Wrap the EOF cause so the allowlisted diagnostic preserves both failure signals.
	upstreamErr := fmt.Errorf("dial https://upstream.invalid?token=secret-token failed: %w", io.EOF)
	entry.Data["error"] = upstreamErr
	line, err := (&LogFormatter{}).Format(entry)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-auth-record", "person@example.com", "person:password", "secret-token"} {
		if strings.Contains(string(line), secret) {
			t.Fatalf("new upstream log field leaked %q: %s", secret, line)
		}
	}
	// UUIDv7 request correlation uses the trailing eight characters, not the prefix.
	if !strings.Contains(string(line), "[5678abcd]") || !strings.Contains(string(line), `auth_id="[REDACTED]"`) || !strings.Contains(string(line), `auth_ref="a1b2c3d4e5f6"`) || !strings.Contains(string(line), "EOF") || !strings.Contains(string(line), "dial_failed") {
		t.Fatalf("safe log lost request correlation or error signals: %s", line)
	}
	if entry.Data["auth_id"] != "private-auth-record" || entry.Data["error"] != upstreamErr {
		t.Fatal("formatter mutated the shared log entry")
	}
}

func TestGinLoggerRedactsErrorsWithoutDroppingJoinKeys(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("X-Session-Affinity", "client-session-123")
	line := serveAndCaptureLogLine(t, req, func(c *gin.Context) {
		_ = c.Error(errors.New("rejected api_key=sk-test-synthetic123 person@example.com account_id=private-account"))
		c.String(http.StatusBadGateway, `{"id":"msg_safe"}`)
	})
	for _, secret := range []string{"sk-test-synthetic123", "person@example.com", "private-account"} {
		if strings.Contains(line, secret) {
			t.Fatalf("Gin error leaked %q: %s", secret, line)
		}
	}
	if !strings.Contains(line, "session=client-session-123 msg=msg_safe compact=no") {
		t.Fatalf("redaction dropped fork join keys: %s", line)
	}
}

type mergeErrorFlushRecorder struct {
	*httptest.ResponseRecorder
	err     error
	flushes int
}

func (w *mergeErrorFlushRecorder) FlushError() error {
	w.flushes++
	return w.err
}

func TestResponseIDWriterPreservesUpstreamFlushErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	want := errors.New("synthetic transport failure")
	recorder := &mergeErrorFlushRecorder{ResponseRecorder: httptest.NewRecorder(), err: want}
	ctx, _ := gin.CreateTestContext(recorder)
	writer := &responseIDWriter{ResponseWriter: ctx.Writer}
	_, _ = writer.WriteString(`{"id":"msg_flush"}`)
	if err := httpwire.FlushResponse(writer); !errors.Is(err, want) || recorder.flushes != 1 {
		t.Fatalf("fork log wrapper swallowed upstream flush error: %v, flushes=%d", err, recorder.flushes)
	}
	if writer.responseID() != "msg_flush" || recorder.Body.String() != `{"id":"msg_flush"}` {
		t.Fatal("error-aware flushing changed the response or its join key")
	}
}
