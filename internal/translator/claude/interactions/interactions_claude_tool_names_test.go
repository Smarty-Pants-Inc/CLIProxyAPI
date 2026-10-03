package interactions

import (
	"context"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// Two declared names that sanitize to the same Claude name must stay distinct,
// and the response must name the requested source function.
func TestInteractionsToolNamesKeepSourceIdentity(t *testing.T) {
	request := []byte(`{"model":"claude-test","input":[{"type":"user_input","content":[{"type":"text","text":"hi"}]},{"type":"function_call","name":"read.info","call_id":"toolu_1","arguments":{}},{"type":"function_result","name":"read.info","call_id":"toolu_1","result":{"ok":true}}],"tools":[{"type":"function","name":"read.info","parameters":{"type":"object"}},{"type":"function","name":"read_info","parameters":{"type":"object"}}],"tool_choice":{"type":"function","name":"read.info"}}`)
	out := ConvertInteractionsRequestToClaude("claude-test", request, false)
	tools := gjson.GetBytes(out, "tools").Array()
	if len(tools) != 2 || tools[0].Get("name").String() == tools[1].Get("name").String() {
		t.Fatalf("colliding declarations: %s", gjson.GetBytes(out, "tools").Raw)
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != tools[0].Get("name").String() {
		t.Fatalf("forced choice %q does not name the declared tool %q", got, tools[0].Get("name").String())
	}
	backend := tools[0].Get("name").String()
	resp := []byte(`{"id":"m","type":"message","role":"assistant","model":"claude-test","content":[{"type":"tool_use","id":"toolu_2","name":"` + backend + `","input":{}}],"stop_reason":"tool_use","usage":{"input_tokens":1,"output_tokens":1}}`)
	got := ConvertClaudeResponseToInteractionsNonStream(context.Background(), "claude-test", request, out, resp, nil)
	if !strings.Contains(string(got), `"name":"read.info"`) {
		t.Fatalf("response does not name the source function read.info: %s", got)
	}
}
