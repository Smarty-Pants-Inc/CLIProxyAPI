package executor

import (
	"fmt"
	"testing"

	"github.com/tidwall/gjson"
)

// Data safety: model-only items are private in non-stream mode; server tools
// and unknown shapes must still latch, including work seen only in a snapshot.
func TestCodexNonStreamFrameCommitsUpstreamWork(t *testing.T) {
	for _, kind := range []string{"message", "reasoning", "function_call", "custom_tool_call", "web_search_call", "file_search_call", "code_interpreter_call", "mcp_call", "computer_call", "image_generation_call", "local_shell_call", "shell_call", "future_server_call", ""} {
		item := fmt.Sprintf(`{"type":%q,"content":[{"type":"output_text","text":"generated"}],"summary":[{"type":"summary_text","text":"thinking"}],"encrypted_content":"encrypted","arguments":"{}","input":"patch"}`, kind)
		for _, event := range []string{"response.output_item.added", "response.output_item.done", "response.created", "response.in_progress", "response.completed", "response.done", "response.incomplete", "response.failed"} {
			t.Run(kind+"/"+event, func(t *testing.T) {
				payload := fmt.Sprintf(`{"type":%q,"response":{"output":[%s]}}`, event, item)
				if event == "response.output_item.added" || event == "response.output_item.done" {
					payload = fmt.Sprintf(`{"type":%q,"item":%s}`, event, item)
				}
				want := kind != "message" && kind != "reasoning" && kind != "function_call" && kind != "custom_tool_call"
				if got := codexNonStreamFrameCommitsUpstreamWork(event, []byte(payload)); got != want {
					t.Fatalf("work=%t want=%t payload=%s", got, want, payload)
				}
			})
		}
	}
	for _, event := range []string{"error", "keepalive", "codex.rate_limits", "codex.response.metadata", "response.output_text.delta", "response.output_text.done", "response.output_text.annotation.added", "response.refusal.delta", "response.refusal.done", "response.reasoning_text.delta", "response.reasoning_text.done", "response.reasoning_summary_text.delta", "response.reasoning_summary_text.done", "response.function_call_arguments.delta", "response.function_call_arguments.done", "response.custom_tool_call_input.delta", "response.custom_tool_call_input.done"} {
		t.Run(event, func(t *testing.T) {
			payload := []byte(fmt.Sprintf(`{"type":%q,"delta":"generated","text":"generated","arguments":"{}","input":"patch"}`, event))
			if codexNonStreamFrameCommitsUpstreamWork(event, payload) {
				t.Fatalf("model event latched: %s", payload)
			}
		})
	}
	for _, event := range []string{"response.content_part.added", "response.content_part.done", "response.reasoning_summary_part.added", "response.reasoning_summary_part.done"} {
		for _, part := range []string{"output_text", "summary_text", "text", "reasoning_text", "refusal", "future_server_part", ""} {
			t.Run(event+"/"+part, func(t *testing.T) {
				payload := []byte(fmt.Sprintf(`{"type":%q,"part":{"type":%q,"text":"generated","refusal":"no"}}`, event, part))
				want := part == "future_server_part" || part == ""
				if got := codexNonStreamFrameCommitsUpstreamWork(event, payload); got != want {
					t.Fatalf("work=%t want=%t payload=%s", got, want, payload)
				}
			})
		}
	}
	for _, payload := range []string{`{"type":"future_server_event"}`, `{"type":"response.web_search_call.in_progress"}`, `{"type":"response.mcp_call_arguments.delta"}`, `{"type":"response.output_item.added"}`, `{}`, `{"type":"response.in_progress","response":{"output":[{"type":"message"},{"type":"mcp_call"}]}}`} {
		t.Run("unknown-or-mixed/"+payload, func(t *testing.T) {
			if !codexNonStreamFrameCommitsUpstreamWork(gjson.Get(payload, "type").String(), []byte(payload)) {
				t.Fatalf("work not latched: %s", payload)
			}
		})
	}
	if codexNonStreamFrameCommitsUpstreamWork("", nil) {
		t.Fatal("empty heartbeat latched")
	}
}
