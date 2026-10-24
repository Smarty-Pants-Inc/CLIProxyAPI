package helps

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// Trust boundary: retain the known scanner failure for operators, never secrets in the
// client error or raw upstream diagnostics in logs (PR #174 round-5 N3).
func TestStreamInvalidLogsSanitizedCause(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	cause := fmt.Errorf("authorization: Bearer diagnostic-secret %s: %w", strings.Repeat("x", 20000), bufio.ErrTooLong)
	var progress StreamProgress
	err := progress.Incomplete(context.Background(), "fixture", "model", 200, "terminal", cause)
	var found bool
	for _, entry := range hook.AllEntries() {
		if entry.Message != "upstream stream invalid" {
			continue
		}
		found = true
		diagnostic, ok := entry.Data["upstream_error"].(string)
		if !ok || diagnostic != bufio.ErrTooLong.Error() || strings.Contains(diagnostic, "diagnostic-secret") || entry.Level != logrus.WarnLevel || entry.Data["code"] != "upstream_stream_invalid" {
			t.Fatalf("unsafe or missing cause: %+v", entry)
		}
	}
	if !found {
		t.Fatal("missing invalid-stream warning")
	}
	if strings.Contains(err.Error(), "diagnostic-secret") || strings.Contains(err.Error(), "authorization") {
		t.Fatal("cause exposed to client")
	}
}
