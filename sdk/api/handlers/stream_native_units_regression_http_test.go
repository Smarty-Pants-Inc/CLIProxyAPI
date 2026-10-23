package handlers_test

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

// PR #174 CI: preserve native units only when inspection leaves the event
// unchanged. A rewritten terminal must replace, not follow, its raw fragments.
func TestCodexMultilineNativeTerminalRewrite(t *testing.T) {
	for _, mode := range []string{"done alias", "output repair"} {
		t.Run(mode, func(t *testing.T) {
			body := reviewRequest(t, "codex", "responses", func(first, terminal string) string {
				if mode == "done alias" {
					terminal = strings.Replace(terminal, "response.completed", "response.done", 1)
				} else {
					first += "data: {\"type\":\"response.output_item.done\",\ndata: \"output_index\":0,\n: keepalive\ndata: \"item\":{\"type\":\"message\",\"id\":\"msg-native\",\"content\":[]}}\n\n"
				}
				terminal = strings.Replace(terminal, "data: {", "data: {\ndata: ", 1)
				return first + terminal
			})
			if strings.Contains(body, "event: error") || strings.Contains(body, "upstream_stream_incomplete") {
				t.Fatalf("rewritten native terminal failed: %s", body)
			}
			count := 0
			for _, line := range strings.Split(body, "\n") {
				data, ok := strings.CutPrefix(line, "data: ")
				if !ok || gjson.Get(data, "type").String() != "response.completed" {
					continue
				}
				count++
				if !gjson.Valid(data) {
					t.Fatalf("invalid terminal JSON: %s", line)
				}
				if mode == "output repair" && gjson.Get(data, "response.output.0.id").String() != "msg-native" {
					t.Fatalf("lost collected output in rewritten terminal: %s", line)
				}
			}
			if count != 1 {
				t.Fatalf("got %d completions, want exactly one: %s", count, body)
			}
		})
	}
}
