package executor

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexTestWithModel gives a mocked Codex event the model the executor sent
// upstream. The fork's Codex model-integrity guard fails closed when
// response.model is missing (smarty-dev#3555: fix the mock, not the guard).
// The event may be a bare JSON object or one SSE "data:" frame.
func codexTestWithModel(event string, upstreamBody []byte) string {
	model := gjson.GetBytes(upstreamBody, "model").String()
	prefix, rest := "", event
	if strings.HasPrefix(rest, "data: ") {
		prefix, rest = "data: ", strings.TrimPrefix(rest, "data: ")
	}
	trimmed := strings.TrimRight(rest, "\n")
	suffix := rest[len(trimmed):]
	if model == "" || !gjson.Get(trimmed, "response").IsObject() || gjson.Get(trimmed, "response.model").Exists() {
		return event
	}
	updated, errSet := sjson.Set(trimmed, "response.model", model)
	if errSet != nil {
		return event
	}
	return prefix + updated + suffix
}
