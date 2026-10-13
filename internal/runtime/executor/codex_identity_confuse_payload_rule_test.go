package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// CLIProxyAPI#111 security pass: a payload rule that sets prompt_cache_key must
// not split the Codex identity across body and headers. The session headers
// follow the final body key, and with identity-confuse on the client still sees
// its own key.

const identityTestOperatorKey = "operator-owned-cache-key"

func identityRuleConfig(enabled bool) *config.Config {
	cfg := identityTestConfig(enabled)
	cfg.Payload = config.PayloadConfig{Override: []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}},
		Params: map[string]any{"prompt_cache_key": identityTestOperatorKey},
	}}}
	return cfg
}

func assertRuleKeyBound(t *testing.T, enabled bool, body []byte, headers http.Header, clientOutput string) {
	t.Helper()
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != identityTestOperatorKey {
		t.Fatalf("upstream prompt_cache_key = %q, want operator key", got)
	}
	if got := codexSessionHeaderValue(headers); got != identityTestOperatorKey {
		t.Fatalf("upstream session header = %q, want it bound to body key %q (headers %v)", got, identityTestOperatorKey, headers)
	}
	if got := headerValueCaseInsensitive(headers, "Conversation_id"); got != "" && got != identityTestOperatorKey {
		t.Fatalf("upstream Conversation_id = %q, want it bound to body key", got)
	}
	if enabled {
		confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
		for _, name := range []string{"Thread-Id", "X-Client-Request-Id"} {
			if got := headers.Get(name); got != identityTestOperatorKey {
				t.Fatalf("upstream %s = %q, want it bound to body key", name, got)
			}
		}
		if headersContain(headers, confused) {
			t.Fatalf("upstream headers still carry the pre-rule remapped key: %v", headers)
		}
		if !strings.Contains(clientOutput, "key="+identityTestCacheKey) || strings.Contains(clientOutput, identityTestOperatorKey) {
			t.Fatalf("client output does not restore the client's own key: %s", clientOutput)
		}
	}
}

func TestCodexPayloadRuleKeyBindsSessionHeaders(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("http/enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityHTTPServer(t, capture)
			exec := NewCodexExecutor(identityRuleConfig(enabled))
			resp, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertRuleKeyBound(t, enabled, body, headers, string(resp.Payload))
		})
		t.Run(fmt.Sprintf("websocket/enabled=%t", enabled), func(t *testing.T) {
			capture := &identityTestCapture{}
			server := newIdentityWebsocketServer(t, capture)
			exec := NewCodexWebsocketsExecutor(identityRuleConfig(enabled))
			resp, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
				Model:   "gpt-5.5",
				Payload: identityTestPayload(),
			}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			body, headers := capture.snapshot()
			assertRuleKeyBound(t, enabled, body, headers, string(resp.Payload))
		})
	}
}
