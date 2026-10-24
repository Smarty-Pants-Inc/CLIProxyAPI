package helps

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

func TestStreamProgressIncompleteDiagnostics(t *testing.T) {
	var progress StreamProgress
	progress.Sent([]byte("first"))
	progress.Sent(nil)
	progress.Sent([]byte("second"))
	cause := errors.New(`{"error":{"code":"fixture_busy","message":"busy","api_key":"not-a-real-key"}}`)
	err := progress.Incomplete(context.Background(), "fixture", "fixture-model", 201, "[DONE]", cause)
	detail := gjson.Get(err.Error(), "error")
	if detail.Get("partial_chunks").Int() != 2 || detail.Get("partial_bytes").Int() != 11 || detail.Get("upstream_status").Int() != 201 || detail.Get("upstream_code").String() != "fixture_busy" {
		t.Fatal(err)
	}
	if detail.Get("type").String() != "upstream_stream_incomplete" || detail.Get("code").String() != "upstream_stream_incomplete" {
		t.Fatal(err)
	}
	if retryable := detail.Get("retryable"); !retryable.IsBool() || !retryable.Bool() {
		t.Fatalf("missing retryable:true for transient upstream EOF: %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatal("lost upstream cause")
	}
	if got := detail.Get("upstream_error").String(); got == "" || gjson.Get(got, "error.api_key").String() == "not-a-real-key" {
		t.Fatalf("unredacted or missing diagnostic: %s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := progress.Incomplete(ctx, "fixture", "fixture-model", 201, "[DONE]", cause); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel classified as upstream failure: %v", err)
	}
}

// Simulate a 901-second stream without sleeping or waiting for an upstream.
func TestStreamProgressIncompleteElapsedWarning(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	progress := StreamProgress{StartedAt: time.Now().Add(-901 * time.Second)}
	progress.Sent([]byte("private-body-sentinel"))
	err := progress.Incomplete(t.Context(), "codex", "fixture-model", 200, "response.completed", io.ErrUnexpectedEOF)
	var incomplete *IncompleteStreamError
	if !errors.As(err, &incomplete) || incomplete.StatusCode() != http.StatusBadGateway || !incomplete.IsRequestScoped() {
		t.Fatalf("classification changed: %v", err)
	}
	entry := hook.LastEntry()
	if entry == nil || entry.Level != log.WarnLevel || entry.Message != "upstream stream incomplete" {
		t.Fatalf("missing warning: %v", entry)
	}
	elapsed, ok := entry.Data["stream_elapsed_seconds"].(float64)
	if !ok || elapsed < 901 || elapsed > 961 {
		t.Fatalf("elapsed=%v, want about 901 seconds", entry.Data["stream_elapsed_seconds"])
	}
	line, errFormat := (&logging.LogFormatter{}).Format(entry)
	if errFormat != nil {
		t.Fatal(errFormat)
	}
	for _, field := range []string{"upstream_error=\"unexpected_EOF\"", "upstream_status=200", "partial_bytes=21", "partial_chunks=1", "stream_elapsed_seconds="} {
		if !strings.Contains(string(line), field) {
			t.Errorf("missing %q: %s", field, line)
		}
	}
	if strings.Contains(string(line), "private-body-sentinel") {
		t.Fatalf("body text in ordinary log: %s", line)
	}
	t.Log(strings.TrimSpace(string(line)))
}
