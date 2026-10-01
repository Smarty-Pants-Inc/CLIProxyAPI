package executor

import "testing"

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
