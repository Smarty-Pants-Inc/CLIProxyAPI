package executor

import (
	"fmt"
	"testing"
)

// Data safety: no replay after a call, including empty-argument announcements
// and work reported only in a created/in-progress/terminal response snapshot.
func TestCodexFrameCommitsUpstreamWorkItems(t *testing.T) {
	for _, kind := range []string{"message", "reasoning", "web_search_call", "file_search_call", "code_interpreter_call", "mcp_call", "computer_call", "function_call", "custom_tool_call", "future_call"} {
		item := fmt.Sprintf(`{"type":%q,"content":[],"summary":[],"arguments":"","input":""}`, kind)
		for _, event := range []string{"response.output_item.added", "response.created", "response.in_progress", "response.completed", "response.done", "response.incomplete", "response.failed"} {
			t.Run(kind+"/"+event, func(t *testing.T) {
				payload := fmt.Sprintf(`{"type":%q,"response":{"output":[%s]}}`, event, item)
				if event == "response.output_item.added" {
					payload = fmt.Sprintf(`{"type":%q,"item":%s}`, event, item)
				}
				want := kind != "message" && kind != "reasoning"
				if got := codexFrameCommitsUpstreamWork(event, []byte(payload)); got != want {
					t.Fatalf("work=%t want=%t payload=%s", got, want, payload)
				}
			})
		}
	}
}
