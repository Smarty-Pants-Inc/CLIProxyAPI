package executor

import (
	"context"
	"strings"
	"testing"
)

// Quota failover must remain disabled after an upstream server tool has started.
func TestCodexWebsocketsExecutor_UnsafeQuotaRefusalStaysInStream(t *testing.T) {
	for name, event := range map[string]string{
		"insufficient_quota":  `{"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"code":"insufficient_quota","message":"You exceeded your current quota"}},"sequence_number":2}`,
		"usage_limit_reached": `{"type":"response.failed","response":{"id":"resp_1","status":"failed","error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":3600}},"sequence_number":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := codexWebsocketServer(t, codexCreatedEvent, WSReplayUnsafeTool, codexInProgressEvent, event)
			defer server.Close()

			req, opts := codexWebsocketRequest()
			result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(true)).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
			if err != nil || result == nil {
				t.Fatalf("ExecuteStream = %v, %v; want an in-stream refusal, not a failover", result, err)
			}
			combined, streamErr := drainChunks(result)
			if streamErr == nil {
				t.Fatal("quota refusal must arrive as an in-stream chunk error")
			}
			if !strings.Contains(combined, `"type":"response.created"`) {
				t.Fatalf("handshake must be flushed before the in-stream refusal: %s", combined)
			}
		})
	}
}
