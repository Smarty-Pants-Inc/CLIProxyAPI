package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

func TestCodexWebsocketsMidstreamErrorDiagnostics(t *testing.T) {
	for _, buffering := range []bool{false, true} {
		for _, raw := range []bool{false, true} {
			for _, kind := range []string{"error", "response.failed"} {
				t.Run(fmt.Sprintf("buffering=%t/raw=%t/%s", buffering, raw, kind), func(t *testing.T) {
					detail := `{"code":"server_error","type":"server_error","message":"busy token=private-secret owner@example.com","api_key":"nested-secret"}`
					event := `{"type":"error","error":` + detail + `}`
					if kind == "response.failed" {
						event = `{"type":"response.failed","response":{"error":` + detail + `}}`
					}
					server := codexWebsocketServer(t, codexCreatedEvent, `{"type":"response.output_text.delta","delta":"partial"}`, event)
					defer server.Close()
					req, opts := codexWebsocketRequest()
					ctx := context.Background()
					if raw {
						ctx = cliproxyexecutor.WithDownstreamWebsocket(ctx)
					}
					result, err := NewCodexWebsocketsExecutor(codexBufferingConfig(buffering)).ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
					if err != nil {
						t.Fatal(err)
					}
					output, streamErr := drainChunks(result)
					if !strings.Contains(output, "partial") || streamErr == nil {
						t.Fatalf("lost partial/error: %s %v", output, streamErr)
					}
					node := gjson.Get(streamErr.Error(), "error")
					if node.Get("code").String() != "server_error" || node.Get("type").String() != "server_error" || !node.Get("retryable").Bool() || node.Get("partial_bytes").Int() <= 0 {
						t.Fatalf("lost diagnostic: %v", streamErr)
					}
					for _, secret := range []string{"private-secret", "owner@example.com", "nested-secret"} {
						if strings.Contains(streamErr.Error(), secret) {
							t.Errorf("leaked %q: %v", secret, streamErr)
						}
					}
					var frameErr *helps.UpstreamStreamError
					if !errors.As(streamErr, &frameErr) {
						t.Fatalf("lost sanitized frame error under replay wrapper: %v", streamErr)
					}
				})
			}
		}
	}
}
