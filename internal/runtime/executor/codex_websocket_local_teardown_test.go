package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/tidwall/gjson"
)

// Failure path: local session shutdown must not be advertised as a retryable
// upstream cut, regardless of whether it occurs before or after client output.
func TestCodexWebsocketLocalTeardownNotIncomplete(t *testing.T) {
	readCh := make(chan codexWebsocketRead)
	close(readCh)
	// A non-nil connection is enough: the closed local channel is read without I/O.
	conn := &websocket.Conn{}
	_, _, closedErr := readCodexWebsocketMessage(context.Background(), &codexWebsocketSession{}, conn, readCh)
	if !errors.Is(closedErr, helps.ErrCodexWebsocketSessionClosed) {
		t.Fatal(closedErr)
	}
	for _, cause := range []error{closedErr, fmt.Errorf("local close: %w", net.ErrClosed)} {
		err := mapCodexWebsocketReadError(cause)
		var invalid *helps.InvalidStreamError
		if !errors.As(err, &invalid) || !errors.Is(err, cause) || !invalid.IsRequestScoped() || gjson.Get(err.Error(), "error.retryable").Bool() {
			t.Fatalf("local teardown misclassified: %v", err)
		}
	}
}
