package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// round3Run sends one request through a real executor and returns the
// upstream body.
func round3Run(t *testing.T, provider string, req core.Request, opts core.Options) []byte {
	t.Helper()
	bodies := make(chan []byte, 1)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		switch {
		case provider == "gemini" && opts.Stream:
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"ok\"}]},\"finishReason\":\"STOP\"}]}\n\n")
		case provider == "gemini":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`)
		case gjson.GetBytes(b, "stream").Bool() || opts.Stream:
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":%q,\"usage\":{}}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\ndata: {\"type\":\"message_stop\"}\n\n", gjson.GetBytes(b, "model").String())
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"m","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`, gjson.GetBytes(b, "model").String())
		}
	}))
	defer s.Close()
	cred := &auth.Auth{ID: t.Name(), Provider: provider, Attributes: map[string]string{"base_url": s.URL, "api_key": "test"}}
	var e auth.ProviderExecutor = NewClaudeExecutor(&config.Config{})
	if provider == "gemini" {
		e = NewGeminiExecutor(&config.Config{})
	}
	if opts.Stream {
		result, err := e.ExecuteStream(t.Context(), cred, req, opts)
		if err != nil {
			t.Fatal(err)
		}
		for c := range result.Chunks {
			if c.Err != nil {
				t.Fatal(c.Err)
			}
		}
	} else if _, err := e.Execute(t.Context(), cred, req, opts); err != nil {
		t.Fatal(err)
	}
	return <-bodies
}

// Compatibility models whose route takes the manual fallback (Gemini or native
// Claude input) must keep the normalizer's lowered or removed effort.
func TestRound3CompatFallbackKeepsNormalizerEffort(t *testing.T) {
	sources := map[translator.Format]string{
		translator.FormatGemini: `{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"generationConfig":{"thinkingConfig":{"thinkingLevel":"high"}}}`,
		translator.FormatClaude: `{"max_tokens":32000,"messages":[{"role":"user","content":"hi"}],"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`,
	}
	for from, source := range sources {
		for _, stream := range []bool{false, true} {
			for _, edit := range []string{"low", "delete", "disable"} {
				t.Run(fmt.Sprintf("%s/%v/%s", from, stream, edit), func(t *testing.T) {
					translator.SetPluginHooks(&round1Normalizer{edit: edit})
					defer translator.SetPluginHooks(nil)
					model := "claude-opus-5-5"
					req := core.Request{Model: model, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: model, IsCompat: true, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high", "none"}, ZeroAllowed: true, DynamicAllowed: true}}}}
					b := round3Run(t, "claude", req, core.Options{SourceFormat: from, ResponseFormat: from, Stream: stream, OriginalRequest: []byte(source)})
					effort := gjson.GetBytes(b, "output_config.effort").String()
					if effort == "high" || (edit == "low" && effort != "low") {
						t.Errorf("normalizer %s undone: %s", edit, b)
					}
					if edit == "disable" && gjson.GetBytes(b, "thinking.type").String() != "disabled" {
						t.Errorf("disabled thinking undone: %s", b)
					}
				})
			}
		}
	}
}

type round3DisplayNormalizer struct{ updateNormalizingHooks }

func (*round3DisplayNormalizer) NormalizeRequest(_ context.Context, _, to translator.Format, _ string, b []byte, _ bool) []byte {
	if to == translator.FormatClaude {
		b, _ = sjson.SetBytes(b, "thinking.display", "omitted")
	}
	return b
}

func (*round3DisplayNormalizer) NormalizeResponseBefore(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

func (*round3DisplayNormalizer) NormalizeResponseAfter(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

// A normalizer that changes only thinking visibility does not own the amount:
// the selected model's max support still recovers the client's xhigh.
func TestRound3DisplayOnlyNormalizerKeepsSelectedMaxEffort(t *testing.T) {
	model := "round3-claude-display"
	registry.GetGlobalRegistry().RegisterClient(t.Name(), "claude", []*registry.ModelInfo{{ID: model, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(t.Name()) })
	translator.SetPluginHooks(&round3DisplayNormalizer{})
	defer translator.SetPluginHooks(nil)
	source := `{"reasoning":{"effort":"xhigh","summary":"auto"},"input":[{"role":"user","content":"hi"}]}`
	for _, compat := range []bool{false, true} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("compat=%v/stream=%v", compat, stream), func(t *testing.T) {
				req := core.Request{Model: model, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: model, IsCompat: compat, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high", "max"}}}}}
				b := round3Run(t, "claude", req, core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse, Stream: stream, OriginalRequest: []byte(source)})
				if effort := gjson.GetBytes(b, "output_config.effort").String(); effort != "max" {
					t.Errorf("display-only normalizer changed effort to %q: %s", effort, b)
				}
			})
		}
	}
}

type round3GeminiNormalizer struct {
	updateNormalizingHooks
	edit string
}

func (h *round3GeminiNormalizer) NormalizeRequest(_ context.Context, _, to translator.Format, _ string, b []byte, _ bool) []byte {
	if to != translator.FormatGemini {
		return b
	}
	switch h.edit {
	case "low":
		b, _ = sjson.SetBytes(b, "generationConfig.thinkingConfig.thinkingLevel", "low")
	case "delete":
		b, _ = sjson.DeleteBytes(b, "generationConfig.thinkingConfig")
	}
	return b
}

func (*round3GeminiNormalizer) NormalizeResponseBefore(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

func (*round3GeminiNormalizer) NormalizeResponseAfter(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

// A normalizer lowering or deleting the translated Gemini thinking config owns
// the effort; the source Responses effort must not be replayed over it.
func TestRound3GeminiNormalizerOwnsEffort(t *testing.T) {
	source := `{"reasoning":{"effort":"high"},"input":[{"role":"user","content":"hi"}]}`
	for _, stream := range []bool{false, true} {
		for _, edit := range []string{"low", "delete"} {
			t.Run(fmt.Sprintf("%v/%s", stream, edit), func(t *testing.T) {
				translator.SetPluginHooks(&round3GeminiNormalizer{edit: edit})
				defer translator.SetPluginHooks(nil)
				model := "gemini-3-pro-preview"
				req := core.Request{Model: model, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: model, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "high"}, DynamicAllowed: true}}}}
				b := round3Run(t, "gemini", req, core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse, Stream: stream, OriginalRequest: []byte(source)})
				level := gjson.GetBytes(b, "generationConfig.thinkingConfig.thinkingLevel").String()
				if level == "high" || (edit == "low" && level != "low") {
					t.Errorf("normalizer %s undone: %s", edit, b)
				}
			})
		}
	}
}
