package helps_test

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	helps "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

type editOrdinaryEffortPluginHooks struct {
	summaryRemovingPluginHooks
	effort         string
	originalEffort string
	called         bool
}

func (h *editOrdinaryEffortPluginHooks) NormalizeRequest(_ context.Context, _, _ sdktranslator.Format, _ string, body []byte, _ bool) []byte {
	h.t.Helper()
	h.called = true
	wantOriginal := h.originalEffort
	if wantOriginal == "" {
		wantOriginal = "high"
	}
	if got := gjson.GetBytes(body, "reasoning.effort").String(); got != wantOriginal {
		h.t.Fatalf("normalizer effort = %q, want %q; body=%s", got, wantOriginal, body)
	}
	var out []byte
	var err error
	if h.effort == "" {
		out, err = sjson.DeleteBytes(body, "reasoning.effort")
	} else {
		out, err = sjson.SetBytes(body, "reasoning.effort", h.effort)
	}
	if err != nil {
		h.t.Fatalf("normalize ordinary effort: %v", err)
	}
	return out
}

func TestPluginOrdinaryResponsesHighEffortCap(t *testing.T) {
	const source = `{"model":"private-high-cap","reasoning":{"effort":"max"},"input":"hi"}`
	hooks := &editOrdinaryEffortPluginHooks{summaryRemovingPluginHooks: summaryRemovingPluginHooks{t: t}, effort: "high", originalEffort: "max"}
	sdktranslator.SetPluginHooks(hooks)
	t.Cleanup(func() { sdktranslator.SetPluginHooks(nil) })
	translated := sdktranslator.TranslateRequestEnvelope(t.Context(), sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex, sdktranslator.RequestEnvelope{Model: "private-high-cap", Body: []byte(source)})
	info := &registry.ModelInfo{ID: "private-high-cap", Type: "codex", Thinking: &registry.ThinkingSupport{Levels: []string{"low", "high", "xhigh"}}}
	req := cliproxyexecutor.Request{Model: info.ID, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": info}}
	body, err := helps.ApplyRequestThinking(translated.Body, req, cliproxyexecutor.Options{}, "openai-response", "codex", "codex", translated.ConfigurationUpdatesChanged)
	if err != nil {
		t.Fatal(err)
	}
	if got := gjson.GetBytes(body, "reasoning.effort").String(); got != "high" {
		t.Fatalf("normalizer high cap was lifted: effort=%q; body=%s", got, body)
	}
}

func TestPluginOrdinaryResponsesEffortNormalization(t *testing.T) {
	const model = "private-ordinary-codex"
	const source = `{"model":"private-ordinary-codex","reasoning":{"effort":"high","summary":"auto"},"input":[{"role":"user","content":"hi"}],"store":false}`
	for _, modelCase := range []struct {
		name string
		info *registry.ModelInfo
	}{
		{name: "user-defined", info: &registry.ModelInfo{ID: model, Type: "codex", UserDefined: true}},
		{name: "configured", info: &registry.ModelInfo{ID: model, Type: "codex", Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}},
	} {
		for _, from := range []sdktranslator.Format{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex} {
			for _, edit := range []struct{ name, effort string }{
				{name: "rewrite", effort: "low"},
				{name: "delete"},
			} {
				t.Run(modelCase.name+"/"+from.String()+"/"+edit.name, func(t *testing.T) {
					hooks := &editOrdinaryEffortPluginHooks{summaryRemovingPluginHooks: summaryRemovingPluginHooks{t: t}, effort: edit.effort}
					sdktranslator.SetPluginHooks(hooks)
					t.Cleanup(func() { sdktranslator.SetPluginHooks(nil) })
					translated := sdktranslator.TranslateRequestEnvelope(t.Context(), from, sdktranslator.FormatCodex, sdktranslator.RequestEnvelope{Model: model, ModelInfo: modelCase.info, Body: []byte(source)})
					if !hooks.called {
						t.Fatal("request plugin normalizer was not called")
					}
					if translated.ConfigurationUpdatesChanged {
						t.Fatal("ordinary effort edit incorrectly reported as an update edit")
					}
					if got := gjson.GetBytes(translated.Body, "reasoning.effort"); got.String() != edit.effort || got.Exists() != (edit.effort != "") {
						t.Fatalf("translated effort = %s, want %q; body=%s", got.Raw, edit.effort, translated.Body)
					}
					req := cliproxyexecutor.Request{Model: model, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": modelCase.info}}
					body, errApply := helps.ApplyRequestThinking(translated.Body, req, cliproxyexecutor.Options{}, from.String(), "codex", "codex", translated.ConfigurationUpdatesChanged)
					if errApply != nil {
						t.Fatalf("ApplyRequestThinking() error = %v", errApply)
					}
					if got := gjson.GetBytes(body, "reasoning.effort"); got.String() != edit.effort || got.Exists() != (edit.effort != "") {
						t.Fatalf("executor replayed ordinary source effort: got %s, want %q; body=%s", got.Raw, edit.effort, body)
					}
					if string(body) != string(translated.Body) {
						t.Fatalf("normalized request changed: got %s, want %s", body, translated.Body)
					}
				})
			}
		}
	}
}
