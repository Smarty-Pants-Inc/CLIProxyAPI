package translator

import (
	"context"
	"testing"
)

func TestNativeOnlySkipsHooksEnabledAfterAdmission(t *testing.T) {
	ctx := WithoutPluginHooks(context.Background())
	r := NewRegistry()
	hooks := &fakePluginHooks{}
	r.SetPluginHooks(hooks)
	body := []byte(`{"model":"m"}`)
	r.TranslateRequestEnvelope(ctx, FormatOpenAIResponse, FormatCodex, RequestEnvelope{Model: "m", Body: body})
	r.NormalizeRequest(ctx, FormatOpenAIResponse, FormatCodex, "m", body, false)
	var param any
	r.TranslateStream(ctx, FormatCodex, FormatOpenAIResponse, "m", body, body, body, &param)
	r.TranslateNonStream(ctx, FormatCodex, FormatOpenAIResponse, "m", body, body, body, &param)
	if len(hooks.calls) != 0 {
		t.Fatalf("restricted hooks=%v", hooks.calls)
	}
	r.TranslateRequest(FormatOpenAIResponse, FormatCodex, "m", body, false)
	if len(hooks.calls) == 0 {
		t.Fatal("unpolicied translation changed")
	}
}
