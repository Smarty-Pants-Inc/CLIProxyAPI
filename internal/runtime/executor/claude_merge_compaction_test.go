package executor

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestClaudeCompactionMergeDispatchAndBothCapsuleFormats(t *testing.T) {
	const block = `{"type":"compaction","content":"signed context","signature":"synthetic/+=="}`
	native := "cpa-claude-compact-v1:" + base64.RawURLEncoding.EncodeToString([]byte(block))
	sealed, err := helps.SealAntigravityCompaction("sealed context", "claude-opus-5-5")
	if err != nil {
		t.Fatal(err)
	}
	req := cliproxyexecutor.Request{Payload: []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":%q},{"type":"compaction","encrypted_content":%q},{"type":"compaction_trigger"}]}`, native, sealed))}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: req.Payload}
	if claudeResponsesCompactionRequested(req, opts) {
		t.Fatal("native Responses trigger was intercepted by text-summary compaction")
	}
	summaryOpts := opts
	summaryOpts.Alt = "responses/compact"
	if !claudeResponsesCompactionRequested(req, summaryOpts) {
		t.Fatal("explicit compact route lost upstream text-summary behavior")
	}
	summaryOpts.Alt = ""
	summaryOpts.ResponseFormat = sdktranslator.FormatClaude
	if !claudeResponsesCompactionRequested(req, summaryOpts) {
		t.Fatal("non-Responses target lost upstream trigger-summary behavior")
	}
	if err := expandClaudeResponsesCompaction(&req, &opts); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(req.Payload), "sealed context") || !strings.Contains(string(req.Payload), native) {
		t.Fatalf("one capsule format was dropped: %s", req.Payload)
	}
	req, opts, state, err := prepareClaudeResponsesCompaction(context.Background(), req, opts)
	if err != nil || !state.Trigger || string(state.Block) != block || strings.Contains(string(req.Payload), "compaction_trigger") {
		t.Fatalf("native compaction preparation changed: %+v %s %v", state, req.Payload, err)
	}
	bad := cliproxyexecutor.Request{Payload: []byte(`{"input":[{"type":"compaction","encrypted_content":"cpa-claude-compact-v1:!!"}]}`)}
	if err := expandClaudeResponsesCompaction(&bad, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := prepareClaudeResponsesCompaction(context.Background(), bad, opts); err == nil {
		t.Fatal("invalid native capsule was silently dropped as foreign")
	}
}

func TestClaudeSignedCompactionReplayAndPayloadBarrier(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			const block = `{"type":"compaction","content":"Summary: PLUM-42","signature":"synthetic-signed/+=="}`
			capsule := "cpa-claude-compact-v1:" + base64.RawURLEncoding.EncodeToString([]byte(block))
			attempts := 0
			transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				attempts++
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				if got := gjson.GetBytes(body, "messages.0.content.0").Raw; got != block {
					t.Fatalf("signed block changed during business preparation: %s", body)
				}
				if gjson.GetBytes(body, "prompt_cache_options.mode").String() != "operator-owned" || gjson.GetBytes(body, "max_tokens").Int() != 1234 {
					t.Fatalf("post-rule cleanup changed user configuration: %s", body)
				}
				if !strings.Contains(strings.Join(req.Header.Values("Anthropic-Beta"), ","), helps.ClaudeCompactionBeta) {
					t.Fatal("signed replay lost its compaction beta")
				}
				response := claudeTestMessageStart("claude-opus-5-5") + "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
					"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n" +
					"data: {\"type\":\"content_block_stop\",\"index\":0}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\ndata: {\"type\":\"message_stop\"}\n\n"
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(response)), Request: req}, nil
			})
			ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
			auth := &cliproxyauth.Auth{ID: "synthetic-compaction", Provider: "claude", Metadata: claudeOAuthTestMetadata(), Attributes: map[string]string{"api_key": "sk-ant-oat01-synthetic", "base_url": "https://claude.invalid", "cloak_mode": "always", "cloak_sensitive_words": "PLUM"}}
			e := NewClaudeExecutor(&config.Config{Payload: config.PayloadConfig{Override: []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "claude-opus-5-5"}}, Params: map[string]any{"max_tokens": 1234, "prompt_cache_options.mode": "operator-owned"}}}}})
			req := cliproxyexecutor.Request{Model: "claude-opus-5-5", Payload: []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":%q},{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]}`, capsule))}
			opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, Stream: stream}
			if stream {
				result, err := e.ExecuteStream(ctx, auth, req, opts)
				if err != nil {
					t.Fatal(err)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Fatal(chunk.Err)
					}
				}
			} else if _, err := e.Execute(ctx, auth, req, opts); err != nil {
				t.Fatal(err)
			}
			if attempts != 1 {
				t.Fatalf("upstream attempts = %d, want 1", attempts)
			}
		})
	}
}
