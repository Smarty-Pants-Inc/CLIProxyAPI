package helps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// StreamProgress counts translated payloads handed to the downstream relay, not
// scanner lines, upstream reads, or keep-alive comments added by the HTTP handler.
// It belongs to one stream attempt and is used only by that attempt's producer.
type StreamProgress struct {
	Bytes  int64
	Chunks int64
}

func (p *StreamProgress) Sent(payload []byte) {
	if len(payload) > 0 {
		p.Bytes += int64(len(payload))
		p.Chunks++
	}
}

// Incomplete reports EOF/read failure before a protocol terminal. The upstream
// handshake status is diagnostic metadata, separate from the proxy failure status.
// Keep these errors request-scoped so a broken connection never cools credentials.
func (p *StreamProgress) Incomplete(ctx context.Context, provider, model string, status int, terminal string, cause error) error {
	fields := logrus.Fields{"provider": provider, "model": model, "upstream_status": status, "partial_bytes": p.Bytes, "partial_chunks": p.Chunks}
	if ctx != nil && ctx.Err() != nil {
		LogWithRequestID(ctx).WithFields(fields).Debug("upstream stream canceled")
		return ctx.Err()
	}
	message := fmt.Sprintf("upstream stream closed before %s (provider=%s, model=%s, upstream_status=%d, partial_bytes=%d, partial_chunks=%d)", terminal, provider, model, status, p.Bytes, p.Chunks)
	detail := map[string]any{"message": message, "type": "upstream_stream_incomplete", "code": "upstream_stream_incomplete"}
	for key, value := range fields {
		detail[key] = value
	}
	if cause != nil {
		// Never copy an arbitrary upstream body (which may contain credentials) into
		// diagnostics. Use the shared bounded, redacted diagnostic representation.
		body := logging.SafeDiagnosticForLog(cause.Error())
		detail["upstream_error"] = body
		fields["upstream_error"] = body
		for _, path := range []string{"error.code", "response.error.code", "code"} {
			if code := gjson.Get(body, path); code.Exists() {
				detail["upstream_code"] = code.Value()
				fields["upstream_code"] = code.Value()
				break
			}
		}
		detail["message"] = message + "; upstream_error=" + body
	}
	fields["type"] = "upstream_stream_incomplete"
	fields["code"] = "upstream_stream_incomplete"
	LogWithRequestID(ctx).WithFields(fields).Warn("upstream stream incomplete")
	body, _ := json.Marshal(map[string]any{"error": detail})
	return &IncompleteStreamError{body: string(body), cause: cause}
}

type IncompleteStreamError struct {
	body  string
	cause error
}

func (e *IncompleteStreamError) Error() string { return e.body }
func (e *IncompleteStreamError) Unwrap() error { return e.cause }
func (e *IncompleteStreamError) StatusCode() int {
	var status interface{ StatusCode() int }
	if errors.As(e.cause, &status) && status.StatusCode() >= 400 {
		return status.StatusCode()
	}
	return http.StatusBadGateway
}
func (*IncompleteStreamError) IsRequestScoped() bool { return true }
