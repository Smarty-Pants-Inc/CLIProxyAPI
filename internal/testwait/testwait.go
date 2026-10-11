// Package testwait bounds hang checks in tests by the test binary deadline
// instead of a fixed wall-clock budget that CI CPU load can exceed.
package testwait

import (
	"context"
	"testing"
	"time"
)

// Floor is the shortest hang bound Context returns.
const Floor = 2 * time.Minute

// reportMargin leaves time to report a hang before the go test -timeout panic.
const reportMargin = 15 * time.Second

// Context returns a context canceled when the test ends or when a hang check
// should give up: shortly before t.Deadline(), never sooner than Floor, and
// Floor when the binary has no deadline. Use it only to catch hangs: wait on
// the event itself and treat ctx.Done() as failure.
func Context(t *testing.T) context.Context {
	t.Helper()
	timeout := Floor
	if deadline, ok := t.Deadline(); ok {
		if remaining := time.Until(deadline) - reportMargin; remaining > timeout {
			timeout = remaining
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	t.Cleanup(cancel)
	return ctx
}
