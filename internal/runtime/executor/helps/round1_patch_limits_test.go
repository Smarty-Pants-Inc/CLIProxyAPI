package helps

import (
	"fmt"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"strings"
	"testing"
)

func TestRound1DispatcherRetainedLimits(t *testing.T) {
	req := []byte(`{"tools":[{"type":"namespace","name":"n","tools":[{"type":"custom","name":"apply_patch"}]}]}`)
	for _, mode := range []string{"bytes", "events", "records"} {
		t.Run(mode, func(t *testing.T) {
			s := NewApplyPatchResponsesState(translator.FormatOpenAIResponse, req, req)
			_, err := s.Transform([]byte(`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"n","arguments":""}}`))
			if err != nil {
				t.Fatal(err)
			}
			limit := 131073
			delta := ""
			if mode == "bytes" {
				limit = 4097
				delta = strings.Repeat("p", 4096)
			}
			if mode == "records" {
				limit = 1025
			}
			for i := 0; i < limit; i++ {
				event := []byte(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","item_id":"a","delta":%q}`, delta))
				if mode == "records" {
					event = []byte(fmt.Sprintf(`{"type":"response.output_item.added","output_index":%d,"item":{"type":"function_call","id":"r%d","call_id":"c%d","name":"n","arguments":""}}`, i+1, i, i))
				}
				s.RememberDispatcherEvent(event)
				_, err = s.Transform(event)
				if err != nil {
					break
				}
			}
			if err == nil {
				t.Errorf("dispatcher %s bound not enforced", mode)
			}
		})
	}
}
