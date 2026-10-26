package executor

import (
	"context"
	"fmt"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// SIWC cleanup must precede the fork's identity/cache-key binding and final
// user rules on both HTTP and WebSocket execute/stream paths.
func TestCodexSIWCMergePayloadBarrierAndIdentity(t *testing.T) {
	for _, websocketPath := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("websocket=%t/stream=%t", websocketPath, stream), func(t *testing.T) {
				cfg := identityRuleConfig(true)
				cfg.Payload.Override[0].Params["max_output_tokens"] = 123
				cfg.Payload.Override[0].Params["store"] = true
				cfg.Payload.Filter = []config.PayloadFilterRule{{
					Models: []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}},
					Params: []string{"instructions"},
				}}
				capture := &identityTestCapture{}
				serverFactory := newIdentityHTTPServer
				if websocketPath {
					serverFactory = newIdentityWebsocketServer
				}
				server := serverFactory(t, capture)
				auth := identityTestAuth(server.URL)
				auth.SetMetadata("use_siwc", true)
				auth.SetMetadata("siwc", map[string]any{"access_token": "test-siwc-token"})
				req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: identityTestPayload()}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
				var result *cliproxyexecutor.StreamResult
				var output string
				var err error
				if websocketPath {
					exec := NewCodexWebsocketsExecutor(cfg)
					if stream {
						result, err = exec.ExecuteStream(context.Background(), auth, req, opts)
					} else {
						response, errExec := exec.Execute(context.Background(), auth, req, opts)
						err, output = errExec, string(response.Payload)
					}
				} else {
					exec := NewCodexExecutor(cfg)
					if stream {
						result, err = exec.ExecuteStream(context.Background(), auth, req, opts)
					} else {
						response, errExec := exec.Execute(context.Background(), auth, req, opts)
						err, output = errExec, string(response.Payload)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				if stream {
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
						output += string(chunk.Payload)
					}
				}
				body, headers := capture.snapshot()
				assertRuleKeyBound(t, true, body, headers, output)
				if headers.Get("Authorization") != "Bearer test-siwc-token" {
					t.Fatal("SIWC did not use its own credential")
				}
				if gjson.GetBytes(body, "max_output_tokens").Int() != 123 || !gjson.GetBytes(body, "store").Bool() || gjson.GetBytes(body, "instructions").Exists() {
					t.Fatalf("SIWC cleanup overwrote final payload rules: %s", body)
				}
			})
		}
	}
}
