package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// Rebinding happens after identity remapping and payload rules. Both the
// original client key and the pre-rule remapped key can still have header
// mirrors, especially on native requests with cloaking disabled.
func TestCodexPayloadRuleRebindNativePaths(t *testing.T) {
	for _, websocketPath := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			for _, confuse := range []bool{false, true} {
				for _, disableCloaking := range []bool{false, true} {
					name := fmt.Sprintf("websocket=%t/stream=%t/identity=%t/disable-cloaking=%t", websocketPath, stream, confuse, disableCloaking)
					t.Run(name, func(t *testing.T) {
						cfg := identityRuleConfig(confuse)
						cfg.Codex.DisableCodexCloaking = disableCloaking
						capture := &identityTestCapture{}
						serverFactory := newIdentityHTTPServer
						if websocketPath {
							serverFactory = newIdentityWebsocketServer
						}
						server := serverFactory(t, capture)
						auth := identityTestAuth(server.URL)
						if got := isCodexCloakingDisabled(cfg, auth); got != disableCloaking {
							t.Fatalf("actual DisableCodexCloaking = %t, want %t", got, disableCloaking)
						}
						headers := identityKeyClientHeaders(identityTestCacheKey)
						headers.Set(codexResponsesLiteHeader, "true")
						headers.Set("X-Codex-Turn-Metadata", fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":%q,"turn_id":"turn","note":"keep","nested":{"prompt_cache_key":"unrelated-cache-key"}}`, identityTestCacheKey, identityTestCacheKey+":0"))
						req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: identityTestPayload()}
						opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatCodex, Headers: headers, Stream: stream}
						var result *cliproxyexecutor.StreamResult
						var err error
						if websocketPath {
							exec := NewCodexWebsocketsExecutor(cfg)
							if stream {
								result, err = exec.ExecuteStream(context.Background(), auth, req, opts)
							} else {
								_, err = exec.Execute(context.Background(), auth, req, opts)
							}
						} else {
							exec := NewCodexExecutor(cfg)
							if stream {
								result, err = exec.ExecuteStream(context.Background(), auth, req, opts)
							} else {
								_, err = exec.Execute(context.Background(), auth, req, opts)
							}
						}
						if err != nil {
							t.Fatalf("execute: %v", err)
						}
						if stream {
							for chunk := range result.Chunks {
								if chunk.Err != nil {
									t.Fatalf("stream chunk: %v", chunk.Err)
								}
							}
						}
						body, upstream := capture.snapshot()
						if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != identityTestOperatorKey {
							t.Errorf("body prompt_cache_key = %q, want %q", got, identityTestOperatorKey)
						}
						if got := codexSessionHeaderValue(upstream); got != identityTestOperatorKey {
							t.Errorf("session = %q, want %q", got, identityTestOperatorKey)
						}
						for key, values := range upstream {
							want := ""
							switch strings.ToLower(key) {
							case "session-id", "session_id", "conversation_id", "thread-id", "x-client-request-id":
								want = identityTestOperatorKey
							case "x-codex-window-id":
								want = identityTestOperatorKey + ":0"
							}
							if want != "" {
								for i, value := range values {
									if value != want {
										t.Errorf("%s[%d] = %q, want %q", key, i, value, want)
									}
								}
							}
						}
						turn := "turn"
						if confuse {
							turn = codexIdentityConfuseUUID(identityTestAuthID, "turn", turn)
						}
						metadata := upstream.Values("X-Codex-Turn-Metadata")
						if len(metadata) == 0 {
							t.Fatal("upstream turn metadata missing")
						}
						wantMetadata := fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":%q,"turn_id":%q,"note":"keep","nested":{"prompt_cache_key":"unrelated-cache-key"}}`, identityTestOperatorKey, identityTestOperatorKey+":0", turn)
						for _, value := range metadata {
							assertCodexRebindMetadata(t, value, wantMetadata)
						}
					})
				}
			}
		}
	}
}

func assertCodexRebindMetadata(t *testing.T, got, want string) {
	t.Helper()
	var gotJSON, wantJSON any
	if err := json.Unmarshal([]byte(got), &gotJSON); err != nil {
		t.Fatalf("invalid metadata %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &wantJSON); err != nil {
		t.Fatalf("invalid expected metadata: %v", err)
	}
	if !reflect.DeepEqual(gotJSON, wantJSON) {
		t.Errorf("metadata = %s, want %s", got, want)
	}
}

// Exercise the final-header seam directly: transport header builders often
// select one value, but custom/model headers and mixed-case aliases can leave
// multiple values at this last barrier. Rebinding must retain benign copies
// and rewrite every exact mirror, regardless of its position or key spelling.
func TestCodexPayloadRuleRebindEveryHeaderValue(t *testing.T) {
	original := identityTestCacheKey
	remapped := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", original)
	for _, old := range []string{original, remapped} {
		for _, targetFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("original=%t/target-first=%t", old == original, targetFirst), func(t *testing.T) {
				state := codexIdentityConfuseState{
					originalPromptCacheKey: original,
					promptCacheKey:         remapped,
					ruleKeyFrom:            remapped,
					ruleKey:                identityTestOperatorKey,
				}
				headers := http.Header{}
				want := http.Header{}
				pair := func(target, benign string) []string {
					if targetFirst {
						return []string{target, benign}
					}
					return []string{benign, target}
				}
				for _, key := range []string{"Thread-Id", "tHrEaD-iD", "X-Client-Request-Id", "x-ClIeNt-ReQuEsT-iD", "X-Codex-Window-Id", "x-CoDeX-wInDoW-iD"} {
					suffix := ""
					if strings.EqualFold(key, "X-Codex-Window-Id") {
						suffix = ":0"
					}
					// A containing string is not an exact mirrored identity.
					benign := "unrelated-" + old + suffix
					headers[key] = pair(old+suffix, benign)
					want[key] = pair(identityTestOperatorKey+suffix, benign)
				}
				for _, key := range []string{"Session-Id", "Conversation_id"} {
					headers[key] = []string{old, "other-session"}
					want[key] = []string{identityTestOperatorKey}
				}
				// Metadata may mirror either field independently. Notes and nested
				// keys deliberately contain the old identity and must not change.
				for _, key := range []string{"X-Codex-Turn-Metadata", "x-CoDeX-tUrN-mEtAdAtA"} {
					benign := fmt.Sprintf(`{"prompt_cache_key":"other","window_id":"other:0","note":%q,"nested":{"prompt_cache_key":%q}}`, old, old)
					headers[key] = pair(fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":%q,"turn_id":"turn","note":%q,"nested":{"prompt_cache_key":%q}}`, old, old+":0", old, old), benign)
					want[key] = pair(fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":%q,"turn_id":"turn","note":%q,"nested":{"prompt_cache_key":%q}}`, identityTestOperatorKey, identityTestOperatorKey+":0", old, old), benign)
					for _, fields := range []struct{ before, after string }{
						{fmt.Sprintf(`{"window_id":%q,"turn_id":"turn"}`, old+":0"), fmt.Sprintf(`{"window_id":%q,"turn_id":"turn"}`, identityTestOperatorKey+":0")},
						{fmt.Sprintf(`{"prompt_cache_key":%q,"turn_id":"turn"}`, old), fmt.Sprintf(`{"prompt_cache_key":%q,"turn_id":"turn"}`, identityTestOperatorKey)},
						{fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":"unrelated:0"}`, old), fmt.Sprintf(`{"prompt_cache_key":%q,"window_id":"unrelated:0"}`, identityTestOperatorKey)},
						{fmt.Sprintf(`{"prompt_cache_key":"other","window_id":%q}`, old+":0"), fmt.Sprintf(`{"prompt_cache_key":"other","window_id":%q}`, identityTestOperatorKey+":0")},
					} {
						headers[key] = append(headers[key], fields.before)
						want[key] = append(want[key], fields.after)
					}
				}
				headers["X-Unrelated"] = []string{old, old + ":0"}
				want["X-Unrelated"] = []string{old, old + ":0"}
				bindCodexHeadersToRuleKey(headers, &state)
				if len(headers) != len(want) {
					t.Errorf("header count = %d, want %d: %v", len(headers), len(want), headers)
				}
				for key, expected := range want {
					got := headers[key]
					if len(got) != len(expected) {
						t.Errorf("%s values = %v, want %v", key, got, expected)
						continue
					}
					for i := range expected {
						if strings.EqualFold(key, "X-Codex-Turn-Metadata") {
							assertCodexRebindMetadata(t, got[i], expected[i])
						} else if got[i] != expected[i] {
							t.Errorf("%s[%d] = %q, want %q", key, i, got[i], expected[i])
						}
					}
				}
			})
		}
	}
	t.Run("no-rule-key", func(t *testing.T) {
		headers := identityKeyClientHeaders(identityTestCacheKey)
		headers["tHrEaD-iD"] = []string{"benign", identityTestCacheKey}
		headers["X-Codex-Turn-Metadata"] = append(headers["X-Codex-Turn-Metadata"], `{"window_id":"other:0"}`)
		want := headers.Clone()
		state := codexIdentityConfuseState{
			enabled:                true,
			originalPromptCacheKey: identityTestCacheKey,
			promptCacheKey:         "pre-rule-key",
			ruleKeyFrom:            identityTestCacheKey,
		}
		bindCodexHeadersToRuleKey(headers, &state)
		if !reflect.DeepEqual(headers, want) {
			t.Fatalf("no ruleKey changed headers: got %v, want %v", headers, want)
		}
	})
}
