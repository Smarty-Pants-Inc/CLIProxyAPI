package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// smarty-dev#7620: matching key-removal intent matters even when comparing the
// pre-rule and final keys yields the same empty string. Without such a rule,
// a header-only session remains legitimate.
func TestCodexPromptCacheRemovalWithoutEarlierKey(t *testing.T) {
	models := []config.PayloadModelRule{{Name: "gpt-5.5", Protocol: "codex"}}
	cases := []struct {
		name    string
		payload config.PayloadConfig
		clear   bool
		final   string
	}{
		{name: "filter", payload: config.PayloadConfig{Filter: []config.PayloadFilterRule{{Models: models, Params: []string{"prompt_cache_key"}}}}, clear: true, final: "absent"},
		{name: "override-empty", payload: config.PayloadConfig{Override: []config.PayloadRule{{Models: models, Params: map[string]any{"prompt_cache_key": ""}}}}, clear: true, final: "empty"},
		{name: "override-null", payload: config.PayloadConfig{Override: []config.PayloadRule{{Models: models, Params: map[string]any{"prompt_cache_key": nil}}}}, clear: true, final: "null"},
		{name: "no-rule"},
		{name: "nonmatching-rule", payload: config.PayloadConfig{Filter: []config.PayloadFilterRule{{Models: []config.PayloadModelRule{{Name: "not-this-model", Protocol: "codex"}}, Params: []string{"prompt_cache_key"}}}}},
		{name: "unrelated-rule", payload: config.PayloadConfig{Override: []config.PayloadRule{{Models: models, Params: map[string]any{"instructions": "operator instructions"}}}}},
	}
	for _, transport := range []string{"http", "native-websocket"} {
		for _, stream := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				for _, earlier := range []string{"absent", "empty", "null"} {
					for _, tc := range cases {
						t.Run(fmt.Sprintf("%s/stream=%t/identity=%t/earlier=%s/%s", transport, stream, enabled, earlier, tc.name), func(t *testing.T) {
							cfg := identityTestConfig(enabled)
							cfg.Payload = tc.payload
							capture := &identityTestCapture{}
							newServer := newIdentityHTTPServer
							if transport == "native-websocket" {
								newServer = newIdentityWebsocketServer
							}
							server := newServer(t, capture)
							exec := NewCodexExecutor(cfg)
							execute, executeStream := exec.Execute, exec.ExecuteStream
							if transport == "native-websocket" {
								wsExec := NewCodexWebsocketsExecutor(cfg)
								execute, executeStream = wsExec.Execute, wsExec.ExecuteStream
							}
							payload := strings.Replace(string(identityTestPayload()), `"prompt_cache_key":"`+identityTestCacheKey+`",`, "", 1)
							if earlier == "empty" {
								payload = strings.Replace(payload, `"model":"gpt-5.5",`, `"model":"gpt-5.5","prompt_cache_key":"",`, 1)
							} else if earlier == "null" {
								payload = strings.Replace(payload, `"model":"gpt-5.5",`, `"model":"gpt-5.5","prompt_cache_key":null,`, 1)
							}
							headers := http.Header{}
							headers.Set("Session-Id", "header-only-session")
							from := sdktranslator.FormatOpenAIResponse
							if transport == "native-websocket" {
								from = sdktranslator.FormatCodex
								headers.Set(codexResponsesLiteHeader, "true")
							}
							req := cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(payload)}
							opts := cliproxyexecutor.Options{SourceFormat: from, Headers: headers, Stream: stream}
							if stream {
								result, err := executeStream(context.Background(), identityTestAuth(server.URL), req, opts)
								if err != nil {
									t.Fatalf("ExecuteStream: %v", err)
								}
								for chunk := range result.Chunks {
									if chunk.Err != nil {
										t.Fatalf("stream chunk: %v", chunk.Err)
									}
								}
							} else if _, err := execute(context.Background(), identityTestAuth(server.URL), req, opts); err != nil {
								t.Fatalf("Execute: %v", err)
							}
							body, upstreamHeaders := capture.snapshot()
							if len(body) == 0 {
								t.Fatal("upstream request was not captured")
							}
							key := gjson.GetBytes(body, "prompt_cache_key")
							if key.String() != "" {
								t.Fatalf("upstream unexpectedly gained a cache key: %s", body)
							}
							if tc.clear {
								switch tc.final {
								case "absent":
									if key.Exists() {
										t.Fatalf("filtered key still exists: %s", body)
									}
								case "empty":
									if key.Type != gjson.String || !key.Exists() {
										t.Fatalf("empty override lost: %s", body)
									}
								case "null":
									if key.Raw != "null" {
										t.Fatalf("null override lost: %s", body)
									}
								}
								for _, name := range []string{"Session-Id", "Session_id", "Conversation_id"} {
									if got := headerValueCaseInsensitive(upstreamHeaders, name); got != "" {
										t.Errorf("%s = %q after matching key-removal rule", name, got)
									}
								}
							} else if got := codexSessionHeaderValue(upstreamHeaders); got != "header-only-session" {
								t.Fatalf("header-only session = %q without matching key-removal rule; headers=%v", got, upstreamHeaders)
							}
						})
					}
				}
			}
		}
	}
}

// Incoming header helpers may flatten arrays, so exercise the final header
// seam directly as well. Mixed-case aliases survive identity Set calls that
// replace canonical arrays, exposing later removed values with cloaking on.
func TestCodexRemovedKeyHeaderCleanupAllValues(t *testing.T) {
	original := identityTestCacheKey
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", original)
	for _, mode := range []string{"direct", "identity-disabled", "identity-enabled"} {
		for _, removedFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/removed-first=%t", mode, removedFirst), func(t *testing.T) {
				headers := identityKeyClientHeaders(original)
				headers["session_id"] = []string{original, "other-session"}
				headers["X-Unrelated"] = []string{original, "keep-other-value"}
				for _, name := range []string{"Thread-Id", "X-Codex-Window-Id", "X-Client-Request-Id"} {
					values := []string{"benign-value", original, confused + ":0"}
					if removedFirst {
						values = []string{original, confused + ":0", "benign-value"}
					}
					headers[name] = values
				}
				metadata := []string{
					`{"prompt_cache_key":"other-key","window_id":"other-window","turn_id":"keep-turn","note":"` + original + `","nested":{"prompt_cache_key":"` + original + `"}}`,
					`{"prompt_cache_key":"` + original + `","window_id":"other-window","turn_id":"keep-turn-a","note":"` + original + `"}`,
					`{"prompt_cache_key":"other-key","window_id":"` + confused + `:0","turn_id":"keep-turn-b","extra":[1,2]}`,
				}
				if removedFirst {
					metadata[0], metadata[2] = metadata[2], metadata[0]
				}
				metadataName := "X-Codex-Turn-Metadata"
				headers[metadataName] = append([]string(nil), metadata...)
				if mode == "identity-enabled" {
					for _, name := range []string{"Thread-Id", "X-Codex-Window-Id", "X-Client-Request-Id", metadataName} {
						alias := strings.ToLower(name[:1]) + name[1:]
						headers[alias] = headers[name]
						delete(headers, name)
					}
					metadataName = strings.ToLower(metadataName[:1]) + metadataName[1:]
				}
				if mode == "direct" {
					clearCodexHeadersForRemovedKey(headers, confused, original)
				} else {
					state := codexIdentityConfuseState{
						enabled: mode == "identity-enabled", authID: identityTestAuthID,
						originalPromptCacheKey: original, promptCacheKey: confused,
						ruleKeyFrom: confused, keyRemoved: true,
					}
					applyCodexIdentityConfuseHeaders(headers, &state)
				}
				for name, values := range headers {
					if codexSessionHeaderKey(name) || strings.EqualFold(name, "Conversation_id") {
						t.Errorf("session header survived removal: %s=%v", name, values)
					}
					for _, mirror := range []string{"Thread-Id", "X-Codex-Window-Id", "X-Client-Request-Id"} {
						if !strings.EqualFold(name, mirror) {
							continue
						}
						for _, value := range values {
							if value == original || value == confused || value == original+":0" || value == confused+":0" {
								t.Errorf("removed key survived in %s value %q (all values %v)", name, value, values)
							}
						}
					}
				}
				for _, name := range []string{"Thread-Id", "X-Codex-Window-Id", "X-Client-Request-Id"} {
					if mode == "identity-enabled" {
						name = strings.ToLower(name[:1]) + name[1:]
					}
					if !reflect.DeepEqual(headers[name], []string{"benign-value"}) {
						t.Errorf("unrelated values in %s changed: %v", name, headers[name])
					}
				}
				if !reflect.DeepEqual(headers["X-Unrelated"], []string{original, "keep-other-value"}) {
					t.Errorf("unrelated header changed: %v", headers["X-Unrelated"])
				}
				gotMetadata := headers[metadataName]
				if len(gotMetadata) != len(metadata) {
					t.Fatalf("metadata values collapsed: got %v, want %d values", gotMetadata, len(metadata))
				}
				for i, before := range metadata {
					var want, got map[string]any
					if err := json.Unmarshal([]byte(before), &want); err != nil {
						t.Fatal(err)
					}
					for _, field := range []string{"prompt_cache_key", "window_id"} {
						if value := want[field]; value == original || value == confused || value == original+":0" || value == confused+":0" {
							delete(want, field)
						}
					}
					if err := json.Unmarshal([]byte(gotMetadata[i]), &got); err != nil {
						t.Fatalf("metadata[%d]: %v", i, err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("metadata[%d] = %v, want only removed-key fields deleted: %v", i, got, want)
					}
				}
			})
		}
	}
}
