package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func TestRound1CodexServerWorkBeforeIdentity(t *testing.T) {
	for _, handshake := range []bool{false, true} {
		t.Run(fmt.Sprint(handshake), func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"search\",\"type\":\"web_search_call\",\"status\":\"in_progress\"}}\n\n")
				if handshake {
					fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":\"gpt-5.4\"}}\n\n")
				}
			}))
			defer server.Close()
			manager := auth.NewManager(nil, nil, nil)
			manager.SetConfig(&config.Config{RequestRetry: 2})
			manager.SetRetryConfig(3, 0, 5)
			for i := 0; i < 2; i++ {
				id := fmt.Sprintf("%s/alternate-%d", t.Name(), i)
				if _, err := manager.Register(t.Context(), &auth.Auth{ID: id, Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "test"}}); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-5.4"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			exec := NewCodexExecutor(&config.Config{})
			manager.RegisterExecutor(exec)
			credential := &auth.Auth{ID: t.Name(), Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "test"}}
			if _, err := manager.Register(t.Context(), credential); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(credential.ID, "codex", []*registry.ModelInfo{{ID: "gpt-5.4"}})
			defer registry.GetGlobalRegistry().UnregisterClient(credential.ID)
			payload := []byte(`{"model":"gpt-5.4","input":"hello"}`)
			result, err := manager.ExecuteStream(t.Context(), []string{"codex"}, core.Request{Model: "gpt-5.4", Payload: payload}, core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAI, Stream: true, OriginalRequest: payload})
			if result != nil {
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						err = chunk.Err
					}
				}
			}
			var stop interface{ IsRequestStop() bool }
			if err == nil || !errors.As(err, &stop) || !stop.IsRequestStop() {
				t.Errorf("missing request-stop marker: %T %v", err, err)
			}
			if calls != 1 {
				t.Errorf("upstream dispatches = %d, want 1", calls)
			}
		})
	}
}

func TestRound1ClaudePatchNone(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprint(stream), func(t *testing.T) {
			u := &claudeCompactionUpstream{}
			s := u.serve(t)
			defer s.Close()
			req := core.Request{Model: "claude-opus-5-5", Payload: []byte(`{"model":"claude-opus-5-5","input":[{"role":"user","content":"hi"}],"tools":[{"type":"custom","name":"apply_patch"}],"tool_choice":"none"}`)}
			if _, err := claudeCompactionRun(t, s, req, stream); err != nil {
				t.Fatal(err)
			}
			body := u.bodies[0]
			if gjson.GetBytes(body, "tools").Exists() && gjson.GetBytes(body, "tool_choice.type").String() != "none" {
				t.Fatalf("patch remains enabled on no-tools turn: %s", body)
			}
		})
	}
}

func (*round1Normalizer) NormalizeResponseBefore(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}
func (*round1Normalizer) NormalizeResponseAfter(_ context.Context, _, _ translator.Format, _ string, _, _, body []byte, _ bool) []byte {
	return body
}

type round1Normalizer struct {
	updateNormalizingHooks
	edit string
}

func (h *round1Normalizer) NormalizeRequest(_ context.Context, _, to translator.Format, _ string, b []byte, _ bool) []byte {
	if to == translator.FormatClaude {
		switch h.edit {
		case "low":
			b, _ = sjson.SetBytes(b, "output_config.effort", "low")
		case "delete":
			b, _ = sjson.DeleteBytes(b, "output_config.effort")
			b, _ = sjson.DeleteBytes(b, "thinking")
		case "disable":
			b, _ = sjson.SetBytes(b, "thinking.type", "disabled")
			b, _ = sjson.DeleteBytes(b, "output_config.effort")
		}
	} else {
		if h.edit == "low" {
			b, _ = sjson.SetBytes(b, "reasoning.effort", "low")
		} else {
			b, _ = sjson.DeleteBytes(b, "reasoning.effort")
		}
	}
	return b
}

func TestRound1ClaudeToolNames(t *testing.T) {
	for _, format := range []translator.Format{translator.FormatGemini, translator.FormatOpenAI} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", format, stream), func(t *testing.T) {
				source := `{"messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"h","type":"function","function":{"name":"get.weather","arguments":"{}"}}]},{"role":"tool","tool_call_id":"h","content":"ok"}],"tools":[{"type":"function","function":{"name":"get.weather","parameters":{"type":"object"}}},{"type":"function","function":{"name":"get_weather","parameters":{"type":"object"}}}],"tool_choice":{"type":"function","function":{"name":"get.weather"}}}`
				if format == translator.FormatGemini {
					source = `{"contents":[{"role":"user","parts":[{"text":"hi"}]},{"role":"model","parts":[{"functionCall":{"name":"get.weather","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"get.weather","response":{"result":"ok"}}}]}],"tools":[{"functionDeclarations":[{"name":"get.weather","parameters":{"type":"object"}},{"name":"get_weather","parameters":{"type":"object"}}]}],"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["get.weather"]}}}`
				}
				var sent []byte
				s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					sent, _ = io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "text/event-stream")
					emit := func(event string) {
						fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.Get(event, "type").String(), event)
					}
					emit(`{"type":"message_start","message":{"id":"m","model":"claude-opus-5-5","role":"assistant","content":[],"usage":{"input_tokens":1}}}`)
					for i, tool := range gjson.GetBytes(sent, "tools").Array() {
						emit(fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"tool_use","id":"c%d","name":%q,"input":{}}}`, i, i, tool.Get("name").String()))
						emit(fmt.Sprintf(`{"type":"content_block_delta","index":%d,"delta":{"type":"input_json_delta","partial_json":"{}"}}`, i))
						emit(fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, i))
					}
					emit(`{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":1}}`)
					emit(`{"type":"message_stop"}`)
				}))
				defer s.Close()
				e := NewClaudeExecutor(&config.Config{})
				credential := &auth.Auth{ID: t.Name(), Provider: "claude", Attributes: map[string]string{"api_key": "test", "base_url": s.URL}}
				req := core.Request{Model: "claude-opus-5-5", Payload: []byte(source)}
				opts := core.Options{SourceFormat: format, ResponseFormat: format, Stream: stream}
				var out []byte
				if stream {
					result, err := e.ExecuteStream(t.Context(), credential, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for c := range result.Chunks {
						if c.Err != nil {
							t.Fatal(c.Err)
						}
						out = append(out, c.Payload...)
					}
				} else {
					result, err := e.Execute(t.Context(), credential, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					out = result.Payload
				}
				tools := gjson.GetBytes(sent, "tools").Array()
				if len(tools) != 2 {
					t.Fatalf("tools=%s", sent)
				}
				first, second := tools[0].Get("name").String(), tools[1].Get("name").String()
				if first == second {
					t.Errorf("tool collision: %q", first)
				}
				if gjson.GetBytes(sent, "tool_choice.name").String() != first {
					t.Errorf("forced choice identity lost: %s", sent)
				}
				found := false
				for _, m := range gjson.GetBytes(sent, "messages").Array() {
					for _, b := range m.Get("content").Array() {
						if b.Get("type").String() == "tool_use" {
							found = true
							if b.Get("name").String() != first {
								t.Errorf("history identity lost: %s", sent)
							}
						}
					}
				}
				if !found {
					t.Error("history tool_use missing")
				}
				if !strings.Contains(string(out), `"name":"get.weather"`) || !strings.Contains(string(out), `"name":"get_weather"`) {
					t.Errorf("client name not reversed: %s", out)
				}
			})
		}
	}
}

func TestRound1NormalizerOwnsEffort(t *testing.T) {
	for _, provider := range []string{"claude", "claude-compat", "codex"} {
		for _, stream := range []bool{false, true} {
			for _, edit := range []string{"low", "delete", "disable"} {
				t.Run(fmt.Sprintf("%s/%v/%s", provider, stream, edit), func(t *testing.T) {
					compat := provider == "claude-compat"
					provider := strings.TrimSuffix(provider, "-compat")
					translator.SetPluginHooks(&round1Normalizer{edit: edit})
					defer translator.SetPluginHooks(nil)
					bodies := make(chan []byte, 1)
					s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						b, _ := io.ReadAll(r.Body)
						bodies <- b
						w.Header().Set("Content-Type", "text/event-stream")
						if provider == "claude" {
							fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"model\":\"claude-opus-5-5\",\"usage\":{}}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":0}}\n\ndata: {\"type\":\"message_stop\"}\n\n")
						} else {
							fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":\"private-codex\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"private-codex\",\"output\":[]}}\n\n")
						}
					}))
					defer s.Close()
					model := "claude-opus-5-5"
					if provider == "codex" {
						model = "private-codex"
					}
					req := core.Request{Model: model, Payload: []byte(`{"reasoning":{"effort":"high"},"input":[{"role":"user","content":"hi"}]}`), Metadata: map[string]any{"cliproxy.resolved_api_key_model_info": &registry.ModelInfo{ID: model, UserDefined: provider == "codex", IsCompat: compat, Thinking: &registry.ThinkingSupport{Levels: []string{"low", "medium", "high", "none"}, ZeroAllowed: true, DynamicAllowed: true}}}}
					cred := &auth.Auth{ID: t.Name(), Provider: provider, Attributes: map[string]string{"base_url": s.URL, "api_key": "test"}}
					opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, ResponseFormat: translator.FormatOpenAIResponse, Stream: stream}
					var e auth.ProviderExecutor = NewClaudeExecutor(&config.Config{})
					if provider == "codex" {
						e = NewCodexExecutor(&config.Config{})
					}
					if stream {
						result, err := e.ExecuteStream(t.Context(), cred, req, opts)
						if err != nil {
							t.Fatal(err)
						}
						for c := range result.Chunks {
							if c.Err != nil {
								t.Fatal(c.Err)
							}
						}
					} else {
						if _, err := e.Execute(t.Context(), cred, req, opts); err != nil {
							t.Fatal(err)
						}
					}
					b := <-bodies
					key := "output_config.effort"
					if provider == "codex" {
						key = "reasoning.effort"
					}
					effort := gjson.GetBytes(b, key).String()
					if effort == "high" || (edit == "low" && effort != "low") {
						t.Errorf("normalizer %s undone: %s", edit, b)
					}
					if provider == "claude" && edit == "disable" && gjson.GetBytes(b, "thinking.type").String() != "disabled" {
						t.Errorf("disabled thinking undone: %s", b)
					}
				})
			}
		}
	}
}
