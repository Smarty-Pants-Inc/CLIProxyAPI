package helps

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestClaudeCompactionSignedBlockAndIterationCacheAccounting(t *testing.T) {
	const block = `{"type":"compaction","content":"signed summary","signature":"synthetic-signature/+=="}`
	stream := []byte("data: {\"type\":\"message_start\",\"message\":{\"model\":\"expected\",\"usage\":{\"input_tokens\":0,\"output_tokens\":0}}}\n\n" +
		"data: {\"type\":\"content_block_start\",\"content_block\":" + block + "}\n\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"compaction"},"usage":{"input_tokens":0,"output_tokens":0,"iterations":[{"input_tokens":11,"output_tokens":7,"cache_creation_input_tokens":3,"cache_read_input_tokens":100},{"input_tokens":2,"output_tokens":4,"cache_creation_input_tokens":5,"cache_read_input_tokens":6}]}}` + "\n\ndata: {\"type\":\"message_stop\"}\n\n")
	result, err := ParseClaudeCompactionStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	if result.InputTokens != 127 || result.OutputTokens != 11 || result.CachedTokens != 106 || result.CacheCreationTokens != 8 {
		t.Fatalf("iteration accounting = %+v", result)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(result.Capsule, claudeCompactionCapsulePrefix))
	if err != nil || string(decoded) != block {
		t.Fatalf("signed block changed: %s, %v", decoded, err)
	}
	prepared, state, err := PrepareClaudeResponsesCompaction([]byte(`{"input":[{"type":"compaction","encrypted_content":"` + result.Capsule + `"}]}`))
	if err != nil || !bytes.Equal(state.Block, decoded) || gjson.GetBytes(prepared, "input.#").Int() != 0 {
		t.Fatalf("signed replay changed: %s %+v %v", prepared, state, err)
	}
	detail := result.UsageDetail()
	if detail.InputTokens != 13 || detail.OutputTokens != 11 || detail.CacheReadTokens != 106 || detail.CacheCreationTokens != 8 || detail.TotalTokens != 138 {
		t.Fatalf("canonical Anthropic accounting = %+v", detail)
	}
	assertUsage := func(payload []byte, path string) {
		t.Helper()
		u := gjson.GetBytes(payload, path)
		if u.Get("input_tokens").Int() != 127 || u.Get("output_tokens").Int() != 11 || u.Get("total_tokens").Int() != 138 || u.Get("input_tokens_details.cached_tokens").Int() != 106 {
			t.Fatalf("Responses accounting = %s", u.Raw)
		}
	}
	assertUsage(BuildClaudeCompactionResponse("expected", result), "usage")
	completed := false
	for _, chunk := range BuildClaudeCompactionStreamChunks("expected", result) {
		idx := bytes.Index(chunk, []byte("data: "))
		if idx >= 0 && gjson.GetBytes(chunk[idx+6:], "type").String() == "response.completed" {
			assertUsage(chunk[idx+6:], "response.usage")
			completed = true
		}
	}
	if !completed {
		t.Fatal("compaction stream did not complete")
	}
}

func TestClaudeCompactionStreamFailsClosedOnErrorsAndTruncation(t *testing.T) {
	const block = "data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"compaction\",\"content\":\"summary\",\"signature\":\"sig\"}}\n\n"
	const delta = "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"compaction\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}\n\n"
	for _, stream := range []string{
		block + delta,
		block + delta + "data: {\"type\":\"error\",\"error\":{\"message\":\"secret-MUST-NOT-LEAK\"}}\n\n",
		block + "data: malformed\n\n",
		block + block + delta + "data: {\"type\":\"message_stop\"}\n\n",
	} {
		result, err := ParseClaudeCompactionStream([]byte(stream))
		if err == nil || result.Capsule != "" || strings.Contains(err.Error(), "secret-MUST-NOT-LEAK") {
			t.Fatalf("unverified compaction released output: %+v %v", result, err)
		}
	}
}
