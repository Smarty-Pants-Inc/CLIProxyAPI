package helps

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/tidwall/gjson"
)

// Trust boundary: proxy replay is legal only before output and before upstream
// side effects; all failures still need their client diagnostic and causal chain.
func TestStreamIncompleteReplayScope(t *testing.T) {
	for _, replaySafe := range []bool{false, true} {
		for _, sent := range []bool{false, true} {
			t.Run(fmt.Sprintf("safe=%t/sent=%t", replaySafe, sent), func(t *testing.T) {
				var progress StreamProgress
				if sent {
					progress.Sent([]byte("payload"))
				}
				incomplete := progress.Incomplete
				if replaySafe {
					incomplete = progress.ReplaySafeIncomplete
				}
				err := incomplete(context.Background(), "fixture", "model", 200, "terminal", io.ErrUnexpectedEOF)
				var streamErr *IncompleteStreamError
				if !errors.As(err, &streamErr) || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatal(err)
				}
				wantReplay := replaySafe && !sent
				if streamErr.IsRequestScoped() == wantReplay || streamErr.IsConnectionLifecycle() != wantReplay {
					t.Fatalf("wrong scope: %+v", streamErr)
				}
				if streamErr.StatusCode() != http.StatusBadGateway {
					t.Fatalf("status=%d", streamErr.StatusCode())
				}
			})
		}
	}
}

func TestStreamLocalLimitIsNotRetryableIncomplete(t *testing.T) {
	var progress StreamProgress
	for _, incomplete := range []func(context.Context, string, string, int, string, error) error{progress.Incomplete, progress.ReplaySafeIncomplete} {
		err := incomplete(context.Background(), "fixture", "model", 200, "terminal", fmt.Errorf("limit: %w", bufio.ErrTooLong))
		var invalid *InvalidStreamError
		if !errors.As(err, &invalid) || !errors.Is(err, bufio.ErrTooLong) || !invalid.IsRequestScoped() || gjson.Get(err.Error(), "error.code").String() != "upstream_stream_invalid" || gjson.Get(err.Error(), "error.retryable").Bool() {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := progress.ReplaySafeIncomplete(ctx, "fixture", "model", 200, "terminal", bufio.ErrTooLong); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
