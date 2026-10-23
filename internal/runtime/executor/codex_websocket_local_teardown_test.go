package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Failure path: auth removal closes local sessions mid-request, but a different
// credential can repair the failure. Size-limit failures are tested separately.
func TestCodexWebsocketLocalTeardownCanRetry(t *testing.T) {
	readCh := make(chan codexWebsocketRead)
	close(readCh)
	conn := &websocket.Conn{}
	_, _, closedErr := readCodexWebsocketMessage(context.Background(), &codexWebsocketSession{}, conn, readCh)
	if !errors.Is(closedErr, helps.ErrCodexWebsocketSessionClosed) {
		t.Fatal(closedErr)
	}
	for _, cause := range []error{closedErr, fmt.Errorf("local close: %w", net.ErrClosed)} {
		err := mapCodexWebsocketReadError(cause)
		var scoped cliproxyexecutor.RequestScopedError
		if !errors.Is(err, cause) || errors.As(err, &scoped) && scoped.IsRequestScoped() || !shouldRetryCodexWebsocketSend(err) {
			t.Fatalf("credential teardown cannot retry: %v", err)
		}
	}
}
