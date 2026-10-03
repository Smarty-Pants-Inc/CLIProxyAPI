package helps

import (
	"fmt"
	"strings"
	"testing"

	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// After a registered folded dispatcher completes a large patch, tiny empty
// deltas and argument-free added events must not each retain an expanded copy.
func TestRound3CompletedDispatcherDoesNotRetainExpandedCopies(t *testing.T) {
	req := []byte(`{"tools":[{"type":"namespace","name":"n","tools":[{"type":"custom","name":"apply_patch"}]}]}`)
	s := NewApplyPatchResponsesState(sdktranslator.FormatOpenAIResponse, req, req)
	s.AddDispatcher("n", "n")
	patch := strings.Repeat("x", 64<<10)
	wrapper := fmt.Sprintf(`{"name":"apply_patch","arguments":{"input":%q}}`, patch)
	for _, raw := range []string{
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"n","arguments":""}}`,
		fmt.Sprintf(`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"a","delta":%q}`, wrapper),
	} {
		if _, err := s.Transform([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	out, err := s.Transform([]byte(`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"n","namespace":"n"}}`))
	if err != nil || len(out) == 0 || gjson.GetBytes(out[len(out)-1], "item.input").String() != patch {
		t.Fatalf("completed patch lost: %v", err)
	}
	retained := func() int {
		total := 0
		for _, call := range s.records {
			for _, e := range call.events {
				total += len(e)
			}
			for _, e := range call.originals {
				total += len(e)
			}
		}
		return total
	}
	base := retained()
	for i := 0; i < 200; i++ {
		for _, raw := range []string{
			`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"a","delta":""}`,
			`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"n","arguments":""}}`,
		} {
			if _, err := s.Transform([]byte(raw)); err != nil {
				t.Fatalf("event %d: %v", i, err)
			}
		}
	}
	if grown := retained() - base; grown > 0 {
		t.Fatalf("tiny post-completion events retained %d extra bytes", grown)
	}
	// A real contradiction after completion still fails.
	if _, err := s.Transform([]byte(`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"a","delta":"more"}`)); err == nil {
		t.Fatal("nonempty delta after completion accepted")
	}
}
