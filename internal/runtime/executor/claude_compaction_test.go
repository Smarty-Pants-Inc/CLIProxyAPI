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
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// The block is returned whole in content_block_start and must round-trip byte
// for byte, including the signature.
const claudeCompactionTestBlock = `{"type":"compaction","content":"Summary: codeword PLUM-42.","signature":"EuYBCkQYsig/+=="}`

type claudeCompactionUpstream struct {
	bodies  [][]byte
	betas   []string
	stop    string
	summary bool
}

func (u *claudeCompactionUpstream) serve(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Error(errRead)
			return
		}
		u.bodies = append(u.bodies, body)
		u.betas = append(u.betas, strings.Join(r.Header.Values("Anthropic-Beta"), ","))
		w.Header().Set("Content-Type", "text/event-stream")
		emit := func(event string) {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.Get(event, "type").String(), event)
		}
		emit(`{"type":"message_start","message":{"id":"msg_cmp","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"usage":{"input_tokens":0,"output_tokens":0}}}`)
		if gjson.GetBytes(body, "compaction").Exists() && u.summary {
			emit(`{"type":"ping"}`)
			emit(`{"type":"content_block_start","index":0,"content_block":` + claudeCompactionTestBlock + `}`)
			emit(`{"type":"content_block_stop","index":0}`)
			emit(`{"type":"message_delta","delta":{"stop_reason":"` + u.stop + `"},"usage":{"input_tokens":0,"output_tokens":0,"iterations":[{"type":"compaction","input_tokens":144,"output_tokens":276}]}}`)
		} else {
			emit(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
			emit(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"PLUM-42"}}`)
			emit(`{"type":"content_block_stop","index":0}`)
			emit(`{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"input_tokens":1,"output_tokens":1}}`)
		}
		emit(`{"type":"message_stop"}`)
	}))
}

func claudeCompactionRequest(input string) core.Request {
	return core.Request{Model: "claude-opus-5-5", Payload: []byte(`{"model":"claude-opus-5-5","stream":true,"input":` + input + `}`)}
}

func claudeCompactionRun(t *testing.T, server *httptest.Server, req core.Request, stream bool) (string, error) {
	t.Helper()
	credential := &auth.Auth{ID: t.Name(), Provider: "claude", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL}}
	opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse, Stream: stream}
	e := NewClaudeExecutor(&config.Config{})
	if !stream {
		resp, err := e.Execute(context.Background(), credential, req, opts)
		return string(resp.Payload), err
	}
	result, err := e.ExecuteStream(context.Background(), credential, req, opts)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	for chunk := range result.Chunks {
		out.Write(chunk.Payload)
		if chunk.Err != nil {
			err = chunk.Err
		}
	}
	return out.String(), err
}

// claudeCompactionItems returns every completed compaction output item.
func claudeCompactionItems(payload string, stream bool) []gjson.Result {
	if !stream {
		var items []gjson.Result
		for _, item := range gjson.Get(payload, "output").Array() {
			if item.Get("type").String() == "compaction" {
				items = append(items, item)
			}
		}
		return items
	}
	var items []gjson.Result
	for _, line := range strings.Split(payload, "\n") {
		data := strings.TrimPrefix(line, "data: ")
		if gjson.Get(data, "type").String() == "response.output_item.done" && gjson.Get(data, "item.type").String() == "compaction" {
			items = append(items, gjson.Get(data, "item"))
		}
	}
	return items
}

func TestClaudeCompactionOnDemandRoundTrip(t *testing.T) {
	for _, stream := range []bool{true, false} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			upstream := &claudeCompactionUpstream{stop: "compaction", summary: true}
			server := upstream.serve(t)
			defer server.Close()

			user := `{"type":"message","role":"user","content":[{"type":"input_text","text":"remember PLUM-42"}]}`
			payload, err := claudeCompactionRun(t, server, claudeCompactionRequest(`[`+user+`,{"type":"compaction_trigger"}]`), stream)
			if err != nil {
				t.Fatal(err)
			}
			items := claudeCompactionItems(payload, stream)
			if len(items) != 1 {
				t.Fatalf("want exactly one compaction item, got %d: %s", len(items), payload)
			}
			if stream && !strings.Contains(payload, `"type":"response.completed"`) {
				t.Fatalf("stream did not complete: %s", payload)
			}
			summaryRequest := upstream.bodies[0]
			if got := gjson.GetBytes(summaryRequest, "compaction.type").String(); got != "summarize" {
				t.Fatalf("summary request compaction = %q: %s", got, summaryRequest)
			}
			if gjson.GetBytes(summaryRequest, "context_management").Exists() || strings.Contains(string(summaryRequest), "compaction_trigger") {
				t.Fatalf("summary request carries context_management or trigger: %s", summaryRequest)
			}
			if !strings.Contains(upstream.betas[0], "compact-2026-09-04") {
				t.Fatalf("summary request beta = %q", upstream.betas[0])
			}

			capsule := items[0].Get("encrypted_content").String()
			next := `[` + user + `,{"type":"compaction","encrypted_content":` + fmt.Sprintf("%q", capsule) + `},{"type":"message","role":"user","content":[{"type":"input_text","text":"codeword?"}]}]`
			if _, err = claudeCompactionRun(t, server, claudeCompactionRequest(next), stream); err != nil {
				t.Fatal(err)
			}
			followUp := upstream.bodies[1]
			first := gjson.GetBytes(followUp, "messages.0")
			if first.Get("role").String() != "assistant" || first.Get("content.0.type").String() != "compaction" {
				t.Fatalf("compaction block is not first: %s", followUp)
			}
			for _, field := range []string{"content", "signature"} {
				if got, want := first.Get("content.0."+field).String(), gjson.Get(claudeCompactionTestBlock, field).String(); got != want {
					t.Fatalf("block %s = %q, want %q", field, got, want)
				}
			}
			if gjson.GetBytes(followUp, "compaction").Exists() || !strings.Contains(upstream.betas[1], "compact-2026-09-04") {
				t.Fatalf("follow-up compaction parameter or beta wrong: beta=%q body=%s", upstream.betas[1], followUp)
			}
		})
	}
}

func TestClaudeCompactionFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, input, stop string
		summary           bool
		status            int
	}{
		{name: "refusal", input: `[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"compaction_trigger"}]`, stop: "refusal", summary: true, status: http.StatusBadGateway},
		{name: "no-block", input: `[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"compaction_trigger"}]`, stop: "end_turn", status: http.StatusBadGateway},
		{name: "bad-capsule", input: `[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},{"type":"compaction","encrypted_content":"cpa-claude-compact-v1:!!"}]`, status: http.StatusBadRequest},
	} {
		for _, stream := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/stream=%t", tc.name, stream), func(t *testing.T) {
				upstream := &claudeCompactionUpstream{stop: tc.stop, summary: tc.summary}
				server := upstream.serve(t)
				defer server.Close()
				payload, err := claudeCompactionRun(t, server, claudeCompactionRequest(tc.input), stream)
				var status interface{ StatusCode() int }
				if !errors.As(err, &status) || status.StatusCode() != tc.status {
					t.Fatalf("want status %d, got %v", tc.status, err)
				}
				if len(claudeCompactionItems(payload, stream)) != 0 || strings.Contains(payload, "PLUM-42") {
					t.Fatalf("failed compaction released output: %s", payload)
				}
			})
		}
	}
}

func TestClaudeCompactionSkipsContextManagementInjection(t *testing.T) {
	payload := []byte(`{"model":"claude-opus-5-5","thinking":{"type":"adaptive"},"compaction":{"type":"summarize"},"messages":[{"role":"user","content":"hi"}]}`)
	got, injected := injectClaudeCodeContextManagement(payload)
	if injected || gjson.GetBytes(got, "context_management").Exists() {
		t.Fatalf("context_management injected on compaction request: %s", got)
	}
	got = reconcileClaudeCodeContextManagement(payload, claudeCodeContextManagementState{eligible: true})
	if gjson.GetBytes(got, "context_management").Exists() {
		t.Fatalf("context_management reconciled onto compaction request: %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
}
