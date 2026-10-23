package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Recorded catch: PR #174 S1. Exercise the real executor/logging boundary in
// both bootstrap and post-bootstrap loops, without an event: keepalive shortcut.
func TestCodexStreamMultilineRecordLoggingAndKeepalive(t *testing.T) {
	for _, buffered := range []bool{false, true} {
		for _, format := range []sdktranslator.Format{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatOpenAI} {
			t.Run(fmt.Sprintf("buffered=%t/%s", buffered, format), func(t *testing.T) {
				const keepalive = "data: {\"type\":\"keepalive\",\ndata: \"sequence_number\":1}\n\n"
				const delta = "data: {\"type\":\"response.output_text.delta\",\ndata: \"output_index\":0,\"content_index\":0,\"delta\":\"whole-record\"}\n\n"
				createdLine := "data:\t  " + codexCreatedEvent
				const singleLine = "data:\t {\"type\":\"response.output_text.delta\", \"output_index\":0,\"content_index\":0,\"delta\":\"single-line\"}"
				body := createdLine + "\n\n" + keepalive + delta + singleLine + "\n\n" + "data: " + codexCompletedEventBody + "\n\n"
				cfg := codexBufferingConfig(buffered)
				cfg.RequestLog = true
				ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
				ctx := context.WithValue(t.Context(), "gin", ginCtx)
				ctx = context.WithValue(ctx, "cliproxy.roundtripper", codexAllocationTransport{stream: body})
				req, opts := codexTestRequest()
				opts.ResponseFormat = format
				opts.Headers = http.Header{"User-Agent": {"grok-shell"}}
				result, err := NewCodexExecutor(cfg).ExecuteStream(ctx, codexTestAuth("https://example.invalid"), req, opts)
				if err != nil {
					t.Fatal(err)
				}
				output, streamErr := drainChunks(result)
				if streamErr != nil {
					t.Fatal(streamErr)
				}
				if (format == sdktranslator.FormatOpenAIResponse && !strings.Contains(output, ": keepalive\n\n")) || strings.Contains(output, `"type":"keepalive"`) {
					t.Fatalf("multiline keepalive was not transformed: %s", output)
				}
				logged, _ := ginCtx.Get("API_RESPONSE")
				logBytes, ok := logged.([]byte)
				if !ok {
					t.Fatalf("API_RESPONSE = %#v, want captured bytes", logged)
				}
				for _, record := range []string{
					createdLine + "\n",
					singleLine + "\n",
					`data: {"type":"keepalive","sequence_number":1}`,
					`data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"whole-record"}`,
				} {
					if !strings.Contains(string(logBytes), record) {
						t.Errorf("log lost or rewrote record %q: %s", record, logBytes)
					}
				}
			})
		}
	}
}

func TestCodexStreamMultilineRecordByteBudget(t *testing.T) {
	// Chat renders this handshake as zero chunks. Its large first fragment must
	// still exhaust the byte budget before the following overload can fail over.
	body := `data: {"type":"response.in_progress","response":{"model":"gpt-5.6-terra","id":"` +
		strings.Repeat("q", codexBootstrapMaxBufferedBytes*2) + "\"}\ndata: }\n\n" +
		"data: " + codexOverloadEvent + "\n\n"
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", codexAllocationTransport{stream: body})
	req, _ := codexTestRequest()
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI, Stream: true}
	result, err := NewCodexExecutor(codexBufferingConfig(true)).ExecuteStream(ctx, codexTestAuth("https://example.invalid"), req, opts)
	if err != nil || result == nil {
		t.Fatalf("assembled record must exhaust byte budget and release stream: result=%v err=%v", result, err)
	}
	_, streamErr := drainChunks(result)
	if streamErr == nil {
		t.Fatal("expected overload delivered in-stream after byte budget release")
	}
}
