package helps

import (
	"context"
	"errors"
	"testing"

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
