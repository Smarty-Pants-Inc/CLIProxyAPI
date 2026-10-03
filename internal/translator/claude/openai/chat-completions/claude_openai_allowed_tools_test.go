package chat_completions

import (
	"testing"

	"github.com/tidwall/gjson"
)

// An allowed-tools entry matching only a declared tool's backend alias must not
// enable that tool.
func TestAllowedToolsBackendAliasGrantsNoPermission(t *testing.T) {
	input := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"read.info","parameters":{"type":"object"}}},{"type":"function","function":{"name":"get_time","parameters":{"type":"object"}}}],"tool_choice":{"type":"allowed_tools","allowed_tools":{"mode":"auto","tools":[{"type":"function","function":{"name":"read_info"}},{"type":"function","function":{"name":"get_time"}}]}}}`)
	for _, convert := range []func(string, []byte, bool) []byte{ConvertOpenAIRequestToClaude, ConvertOpenAIRequestToClaudeWithCompat} {
		out := convert("m", input, false)
		tools := gjson.GetBytes(out, "tools").Array()
		if len(tools) != 1 || tools[0].Get("name").String() != "get_time" {
			t.Fatalf("allowed tools = %s, want only get_time", gjson.GetBytes(out, "tools").Raw)
		}
	}
}
