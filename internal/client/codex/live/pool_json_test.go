package live

import (
	"strings"
	"testing"
)

func TestPoolLiveJSONShapeRejectsAmbiguityAndUnboundedDepth(t *testing.T) {
	for _, payload := range []string{`{}`, `{"sdp":"offer","session":{"model":"gpt-live-1-codex"}}`, `{"array":[true,false,null,1e100,{"text":"ok"}]}`} {
		if !validUniqueJSONObject([]byte(payload)) {
			t.Errorf("valid shape rejected: %s", payload)
		}
	}
	for _, payload := range []string{`[]`, `{}null`, `{"type":"response.create","type":"session.close"}`, `{"type":"response.create","\u0074ype":"session.close"}`, `{"content":[{"type":"input_audio","type":"input_text"}]}`, `{"deep":` + strings.Repeat("[", maxPoolJSONDepth+1) + `null` + strings.Repeat("]", maxPoolJSONDepth+1) + `}`} {
		if validUniqueJSONObject([]byte(payload)) {
			t.Errorf("unsafe shape accepted: %s", payload)
		}
	}
	invalidUTF8 := append([]byte(`{"text":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`"}`)...)
	if validUniqueJSONObject(invalidUTF8) {
		t.Fatal("invalid UTF-8 accepted")
	}
}
