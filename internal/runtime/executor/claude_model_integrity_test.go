package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestClaudeMessagesModelIntegrity(t *testing.T) {
	t.Run("OAuthStartupCancellation", TestClaudeExecutor_ExecuteStreamOAuthStartupCancellationIsRequestScoped)
	t.Run("OAuthStreamCancellation", TestClaudeExecutor_ExecuteStreamOAuthCancellationIsRequestScoped)
	t.Run("FastTranslatedNonstreamRepeatedStart", func(t *testing.T) {
		attempts := 0
		transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			attempts++
			body, errRead := io.ReadAll(req.Body)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if !isAnthropicUpstreamURL(req.URL) || !claudeRequestIsFast(req, body) || !gjson.GetBytes(body, "stream").Bool() {
				t.Fatalf("expected fast Anthropic upstream stream, got %s: %s", req.URL, body)
			}
			if got := gjson.GetBytes(body, "model").String(); got != "claude-opus-5-5" {
				t.Fatalf("unexpected upstream model %q", got)
			}
			const start = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fast\",\"model\":\"claude-opus-5-5\"}}\n\n"
			const content = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"MUST_NOT_LEAK\"}}\n\n"
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(start + content + start)),
				Request:    req,
			}, nil
		})
		ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
		credential := &auth.Auth{ID: t.Name(), Attributes: map[string]string{"api_key": "sk-ant-api03-synthetic"}}
		response, err := NewClaudeExecutor(&config.Config{}).Execute(ctx, credential, core.Request{
			Model:   "claude-opus-5-5",
			Payload: []byte(`{"model":"claude-opus-5-5","max_tokens":100,"speed":"fast","messages":[{"role":"user","content":"proof"}]}`),
		}, core.Options{SourceFormat: translator.FormatClaude, ResponseFormat: translator.FormatOpenAI})
		status, ok := err.(interface{ StatusCode() int })
		if !ok || status.StatusCode() != http.StatusBadGateway {
			t.Fatalf("outermost error = %T %v, want status 502", err, err)
		}
		requestScoped, ok := err.(core.RequestScopedError)
		if !ok || !requestScoped.IsRequestScoped() {
			t.Fatalf("outermost error = %T %v, want request scope", err, err)
		}
		if !strings.Contains(err.Error(), "model_mismatch") || len(response.Payload) != 0 || attempts != 1 {
			t.Fatalf("want one failed identity attempt without output, got attempts=%d payload=%q error=%v", attempts, response.Payload, err)
		}
	})
	const model = "claude-opus-5-5"
	markers := []string{"MUST_NOT_LEAK", "MUST_NOT_CALL", "MUST_NOT_EXECUTE", "proof-call"}
	for _, oauth := range []bool{false, true} {
		for _, translated := range []bool{false, true} {
			for _, stream := range []bool{false, true} {
				for _, identity := range []string{"exact", "exact-normalized", "exact-suffix", "wrong", "wrong-normalized", "missing", "content-before-start"} {
					t.Run(fmt.Sprintf("oauth=%t/translated=%t/stream=%t/%s", oauth, translated, stream, identity), func(t *testing.T) {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							body, errRead := io.ReadAll(r.Body)
							if errRead != nil {
								t.Error(errRead)
								return
							}
							if got := gjson.GetBytes(body, "model").String(); got != model {
								t.Errorf("upstream model = %q, want %q", got, model)
							}
							message := map[string]any{"id": "msg_proof", "type": "message", "role": "assistant", "content": []any{}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
							if identity != "missing" {
								message["model"] = model
								if identity == "wrong" {
									message["model"] = "wrong-model"
								}
								if identity == "wrong-normalized" {
									message["model"] = "public-alias"
								}
							}
							blocks := []any{map[string]any{"type": "text", "text": markers[0]}, map[string]any{"type": "tool_use", "id": markers[3], "name": markers[1], "input": map[string]string{"value": markers[2]}}}
							if gjson.GetBytes(body, "stream").Bool() {
								w.Header().Set("Content-Type", "text/event-stream")
								emit := func(event any) {
									data, _ := json.Marshal(event)
									fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.GetBytes(data, "type").String(), data)
								}
								if identity == "content-before-start" {
									emit(map[string]any{"type": "content_block_start", "index": 0, "content_block": blocks[0]})
								}
								emit(map[string]any{"type": "ping"})
								emit(map[string]any{"type": "message_start", "message": message})
								for i, block := range blocks {
									emit(map[string]any{"type": "content_block_start", "index": i, "content_block": block})
									if i == 0 {
										emit(map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]string{"type": "text_delta", "text": markers[0]}})
									} else {
										emit(map[string]any{"type": "content_block_delta", "index": i, "delta": map[string]string{"type": "input_json_delta", "partial_json": `{"value":"MUST_NOT_EXECUTE"}`}})
									}
									emit(map[string]any{"type": "content_block_stop", "index": i})
								}
								emit(map[string]any{"type": "message_delta", "delta": map[string]string{"stop_reason": "tool_use"}, "usage": map[string]int{"output_tokens": 1}})
								emit(map[string]any{"type": "message_stop"})
							} else {
								message["content"] = blocks
								message["stop_reason"] = "tool_use"
								w.Header().Set("Content-Type", "application/json")
								_ = json.NewEncoder(w).Encode(message)
							}
						}))
						defer server.Close()
						credential := &auth.Auth{ID: t.Name(), Provider: "claude", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL}}
						if oauth {
							credential.Attributes["api_key"] = "sk-ant-oat-synthetic"
							credential.Metadata = claudeOAuthCancellationTestMetadata()
						}
						e := NewClaudeExecutor(&config.Config{})
						req := core.Request{Model: model, Payload: []byte(`{"model":"claude-opus-5-5","max_tokens":100,"messages":[{"role":"user","content":"proof"}]}`)}
						if identity == "exact-normalized" || identity == "wrong-normalized" {
							req.Model = "public-alias"
							e.upstreamModelNormalizer = func(string) string { return model }
						}
						if identity == "exact-suffix" {
							req.Model += "(8192)"
						}
						opts := core.Options{SourceFormat: translator.FormatClaude}
						if translated {
							opts.ResponseFormat = translator.FromString("openai")
						}
						var payload strings.Builder
						var err error
						if stream {
							var result *core.StreamResult
							result, err = e.ExecuteStream(context.Background(), credential, req, opts)
							if result != nil {
								for chunk := range result.Chunks {
									payload.Write(chunk.Payload)
									if chunk.Err != nil {
										err = chunk.Err
									}
								}
							}
						} else {
							var response core.Response
							response, err = e.Execute(context.Background(), credential, req, opts)
							payload.Write(response.Payload)
						}
						positive := strings.HasPrefix(identity, "exact") || (identity == "content-before-start" && !stream && !translated)
						if positive {
							if err != nil {
								t.Fatal(err)
							}
							for _, marker := range markers {
								if !strings.Contains(payload.String(), marker) {
									t.Errorf("verified response lost %q: %s", marker, payload.String())
								}
							}
						} else {
							var mismatch *helps.ClaudeModelMismatchError
							if !errors.As(err, &mismatch) || mismatch.StatusCode() != http.StatusBadGateway || !mismatch.IsRequestScoped() {
								t.Fatalf("want request-scoped 502 model_mismatch, got %v", err)
							}
							if payload.Len() != 0 {
								t.Fatalf("unverified payload escaped: %s", payload.String())
							}
						}
					})
				}
			}
		}
	}
}
