package helps

import (
	"errors"
	"net/http"
)

// ErrCodexWebsocketSessionClosed identifies local teardown, not an upstream cut.
var ErrCodexWebsocketSessionClosed = errors.New("codex websockets executor: session read channel closed")

// InvalidStreamError reports a local stream limit that replay cannot
// repair. Keep its diagnostic bounded and do not disclose arbitrary cause text.
type InvalidStreamError struct{ cause error }

func NewInvalidStreamError(cause error) error { return &InvalidStreamError{cause: cause} }
func (*InvalidStreamError) Error() string {
	return `{"error":{"code":"upstream_stream_invalid","type":"server_error","message":"upstream stream exceeds a local limit","retryable":false}}`
}
func (e *InvalidStreamError) Unwrap() error       { return e.cause }
func (*InvalidStreamError) StatusCode() int       { return http.StatusBadGateway }
func (*InvalidStreamError) IsRequestScoped() bool { return true }
