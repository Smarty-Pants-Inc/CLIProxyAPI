package executor

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// Recorded catch: PR #174 F1. Exercise terminal detection through both executor
// loops: a held handshake and a stream already released by an output delta.
func TestCodexStreamLeadingEmptyDataLines(t *testing.T) {
	// Include canonical usage fields so normal usage enrichment is a no-op.
	terminal := strings.Replace(codexCompletedEventBody, `"total_tokens":2`, `"total_tokens":2,"output_tokens_details":{"reasoning_tokens":0},"input_tokens_details":{"cached_tokens":0}`, 1)
	for _, buffered := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			for _, count := range []int{2, 3} {
				t.Run(fmt.Sprintf("buffered=%t/partial=%t/empty=%d", buffered, partial, count), func(t *testing.T) {
					body := "data: " + codexCreatedEvent + "\n\n"
					if partial {
						body += "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"partial\"}\n\n"
					}
					body += strings.Repeat("data:\n", count) + "data: " + terminal + "\n\n"
					ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", codexAllocationTransport{stream: body})
					req, opts := codexTestRequest()
					result, err := NewCodexExecutor(codexBufferingConfig(buffered)).ExecuteStream(ctx, codexTestAuth("https://example.invalid"), req, opts)
					if err != nil {
						t.Fatal(err)
					}
					output, streamErr := drainChunks(result)
					if streamErr != nil || strings.Contains(output, "upstream_stream_incomplete") {
						t.Fatalf("valid terminal reported incomplete: err=%v output=%s", streamErr, output)
					}
					if !strings.HasSuffix(output, "data: "+terminal) {
						t.Fatalf("terminal not delivered intact: %s", output)
					}
				})
			}
		}
	}
}
