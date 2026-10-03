package common

import (
	"fmt"
	"strings"
	"testing"
)

func TestRound1PatchCompleteSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name, source, final string
		bad                 bool
	}{
		{"conflicting complete", `{"input":"p"}`, `{"input":"pq"}`, true},
		{"equivalent complete", `{"input":"p"}`, `{ "input" : "p" }`, false},
		{"partial recovery", `{"input":"p`, `{"input":"pq"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := NewApplyPatchResponsesBridge(patchResponsesRequest)
			patchSend(t, b, patchEvent("response.output_item.added", 0, patchItem("function_call", "fc1", "c1", "apply_patch", "")))
			patchSend(t, b, []byte(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","output_index":0,"delta":%s}`, patchJSON(tc.source))))
			_, err := b.Transform([]byte(fmt.Sprintf(`{"type":"response.function_call_arguments.done","output_index":0,"arguments":%s}`, patchJSON(tc.final))))
			if (err != nil) != tc.bad {
				t.Fatalf("snapshot error = %v, want rejection=%v", err, tc.bad)
			}
		})
	}
}

func TestRound1PatchRetainedInputLimit(t *testing.T) {
	b := NewApplyPatchResponsesBridge(patchResponsesRequest)
	patchSend(t, b, patchEvent("response.output_item.added", 0, patchItem("function_call", "fc1", "c1", "apply_patch", "")))
	patchSend(t, b, []byte(`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"input\":\""}`))
	event := []byte(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","output_index":0,"delta":%s}`, patchJSON(strings.Repeat("p", 4096))))
	var err error
	for i := 0; i < 4097; i++ {
		_, err = b.Transform(event)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("retained input over 16 MiB accepted")
	}
}

func TestRound1PatchFragmentedValidInput(t *testing.T) {
	b := NewApplyPatchResponsesBridge(patchResponsesRequest)
	patchSend(t, b, patchEvent("response.output_item.added", 0, patchItem("function_call", "fc1", "c1", "apply_patch", "")))
	input := strings.Repeat("p", 65536)
	arguments := `{"input":"` + input + `"}`
	for i := 0; i < len(arguments); i += 16 {
		end := i + 16
		if end > len(arguments) {
			end = len(arguments)
		}
		patchSend(t, b, []byte(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","output_index":0,"delta":%s}`, patchJSON(arguments[i:end]))))
	}
	patchSend(t, b, []byte(fmt.Sprintf(`{"type":"response.function_call_arguments.done","output_index":0,"arguments":%s}`, patchJSON(arguments))))
}
