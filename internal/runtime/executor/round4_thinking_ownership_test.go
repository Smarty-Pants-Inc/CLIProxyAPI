package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// round4LevelPaths are the thinking level fields of the Antigravity (wrapped
// Gemini), Vertex (Gemini) and native Interactions target bodies.
var round4LevelPaths = []string{
	"request.generationConfig.thinkingConfig.thinkingLevel",
	"generationConfig.thinkingConfig.thinkingLevel",
	"generation_config.thinking_level",
}

// round4Normalizer lowers the translated thinking amount of the target body.
type round4Normalizer struct {
	updateNormalizingHooks
	target string
}

func (h *round4Normalizer) NormalizeRequest(_ context.Context, _, to translator.Format, _ string, b []byte, _ bool) []byte {
	path := map[string]string{"antigravity": round4LevelPaths[0], "gemini": round4LevelPaths[1], "interactions": round4LevelPaths[2]}[to.String()]
	if path == "" || to.String() != h.target {
		return b
	}
	b, _ = sjson.SetBytes(b, path, "low")
	return b
}

func (*round4Normalizer) NormalizeResponseBefore(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

func (*round4Normalizer) NormalizeResponseAfter(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

// A suffix-free Responses request whose only effort is an explicit high
// configuration_update must not have that update replayed over a normalizer
// that lowered the translated amount, on Antigravity, Vertex and native
// Interactions, stream and nonstream (round-4 security finding 2 / Astra 3).
func TestRound4NormalizerOwnsEffortOverSourceUpdate(t *testing.T) {
	model := "gemini-3-pro-preview"
	source := `{"model":"` + model + `","input":[{"type":"configuration_update","reasoning":{"effort":"high"}},{"role":"user","content":"hi"}]}`
	for _, tc := range []struct{ provider, target string }{
		{"antigravity", "antigravity"},
		{"vertex", "gemini"},
		{"gemini-interactions", "interactions"},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", tc.provider, stream), func(t *testing.T) {
				translator.SetPluginHooks(&round4Normalizer{target: tc.target})
				defer translator.SetPluginHooks(nil)
				bodies := make(chan []byte, 8)
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					select {
					case bodies <- b:
					default:
					}
					candidate := `{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`
					if tc.provider == "antigravity" {
						candidate = `{"response":` + candidate + `}`
					}
					if strings.Contains(r.URL.Path, "stream") || strings.Contains(r.URL.RawQuery, "sse") || gjson.GetBytes(b, "stream").Bool() {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprint(w, "data: "+candidate+"\n\n")
						return
					}
					w.Header().Set("Content-Type", "application/json")
					fmt.Fprint(w, candidate)
				}))
				defer s.Close()
				cred := &auth.Auth{ID: t.Name(), Provider: tc.provider, Attributes: map[string]string{"base_url": s.URL, "api_key": "test"}}
				var e auth.ProviderExecutor
				switch tc.provider {
				case "antigravity":
					e = NewAntigravityExecutor(&config.Config{RequestRetry: 1})
					cred.Attributes = map[string]string{"base_url": s.URL}
					cred.Metadata = map[string]any{"access_token": "token", "project_id": "project-1", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}
				case "vertex":
					e = NewGeminiVertexExecutor(&config.Config{})
				default:
					e = NewGeminiInteractionsExecutor(&config.Config{})
				}
				req := core.Request{Model: model, Payload: []byte(source), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: model, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "high"}, DynamicAllowed: true}}}}
				opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse, Stream: stream, OriginalRequest: []byte(source)}
				// Only the dispatched request body matters; response translation errors are irrelevant.
				if stream {
					if result, err := e.ExecuteStream(t.Context(), cred, req, opts); err == nil {
						for range result.Chunks {
						}
					}
				} else {
					_, _ = e.Execute(t.Context(), cred, req, opts)
				}
				var b []byte
				select {
				case b = <-bodies:
				default:
					t.Fatal("no upstream request")
				}
				level := ""
				for _, path := range round4LevelPaths {
					if v := gjson.GetBytes(b, path); v.Exists() {
						level = v.String()
					}
				}
				if level != "low" {
					t.Errorf("normalizer's low level replaced by %q (source update replayed): %s", level, b)
				}
			})
		}
	}
}
