package executor

import (
	"strings"
	"testing"
)

func TestPolicyModel(t *testing.T) {
	for _, body := range []string{`{"model":"a","tools":[{"type":"image_generation","Type":"function"}]}`, `{"model":"a","tools":[{"type":"image_generation","type":"function"}]}`, `{"model":"a","model":"b"}`, `{"Model":"b"}`, `{"model":"a"} {}`, `{"model":"a","tools":[{"type":"image_generation"}]}`, `{"model":"a","tools":[{"type":"function","name":"image_gen.imagegen"}]}`} {
		if _, err := PolicyModel([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	if model, err := PolicyModel([]byte(`{"model":"gpt-6.1-sol","tools":[{"type":"function","name":"read"}]}`)); err != nil || model != "gpt-6.1-sol" {
		t.Fatalf("model=%q err=%v", model, err)
	}
}

// F29: deep nesting is refused by a bound, before the duplicate-field walk can grow without limit.
func TestPolicyModelRejectsDeepNesting(t *testing.T) {
	deep := strings.Repeat("[", 200000)
	for name, body := range map[string]string{
		"complete":   `{"model":"a","x":` + deep + strings.Repeat("]", 200000) + `}`,
		"incomplete": `{"model":"a","x":` + deep,
		"shallow513": `{"model":"a","x":` + strings.Repeat("[", 513) + strings.Repeat("]", 513) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PolicyModel([]byte(body)); err == nil || !strings.Contains(err.Error(), "invalid or too deeply nested JSON") {
				t.Fatalf("err=%v, want bounded nesting refusal", err)
			}
		})
	}
	if model, err := PolicyModel([]byte(`{"model":"a","x":` + strings.Repeat("[", 500) + strings.Repeat("]", 500) + `}`)); err != nil || model != "a" {
		t.Fatalf("depth 500: model=%q err=%v", model, err)
	}
}
