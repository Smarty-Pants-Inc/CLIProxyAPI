package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestRound1KimiPatchSSEBoundary(t *testing.T) {
	for _, mode := range []string{"fragmented-valid", "limit", "conflicting-complete", "equivalent-complete", "partial-completion"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				emit := func(event string) bool { _, err := fmt.Fprintf(w, "data: %s\n\n", event); return err == nil }
				emit(`{"type":"response.created","response":{"id":"r","model":"kimi-k2.5"}}`)
				emit(`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"apply_patch","arguments":""}}`)
				delta := func(value string) bool {
					return emit(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","output_index":0,"item_id":"a","delta":%q}`, value))
				}
				final := `{"input":"p"}`
				switch mode {
				case "limit":
					delta(`{"input":"`)
					part := strings.Repeat("p", 4096)
					for i := 0; i < 4097; i++ {
						if !delta(part) {
							return
						}
					}
					delta(`"}`)
					final = `{"input":"` + strings.Repeat("p", 4096*4097) + `"}`
				case "fragmented-valid":
					final = `{"input":"` + strings.Repeat("p", 1<<20) + `"}`
					for i := 0; i < len(final); i += 16 {
						end := i + 16
						if end > len(final) {
							end = len(final)
						}
						if !delta(final[i:end]) {
							return
						}
					}
				case "conflicting-complete":
					delta(`{"input":"p"}`)
					final = `{"input":"pq"}`
				case "equivalent-complete":
					delta(`{"input":"p"}`)
					final = `{ "input" : "p" }`
				case "partial-completion":
					delta(`{"input":"p`)
					final = `{"input":"pq"}`
				}
				emit(fmt.Sprintf(`{"type":"response.function_call_arguments.done","output_index":0,"item_id":"a","arguments":%q}`, final))
				emit(fmt.Sprintf(`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"a","call_id":"c","name":"apply_patch","arguments":%q}}`, final))
				emit(`{"type":"response.completed","response":{"id":"r","output":[]}}`)
			}))
			defer s.Close()
			e := NewKimiExecutor(&config.Config{})
			result, err := e.ExecuteStream(t.Context(), &auth.Auth{ID: t.Name(), Provider: "kimi", Attributes: map[string]string{"api_key": "test", "base_url": s.URL}}, core.Request{Model: "kimi-k2.5", Payload: []byte(`{"input":[],"tools":[{"type":"custom","name":"apply_patch"}]}`)}, core.Options{SourceFormat: translator.FormatOpenAIResponse})
			if err != nil {
				t.Fatal(err)
			}
			failures, completed, done := 0, 0, 0
			for c := range result.Chunks {
				if c.Err != nil {
					err = c.Err
				}
				failures += strings.Count(string(c.Payload), `"type":"response.failed"`)
				completed += strings.Count(string(c.Payload), `"type":"response.completed"`)
				done += strings.Count(string(c.Payload), `"type":"response.custom_tool_call_input.done"`)
			}
			bad := mode == "limit" || mode == "conflicting-complete"
			if bad {
				if err == nil || failures != 1 || completed != 0 {
					t.Errorf("unsafe patch succeeded: err=%v failures=%d completed=%d", err, failures, completed)
				}
			} else if err != nil || completed != 1 || done != 1 {
				t.Errorf("valid patch failed: err=%v completed=%d inputDone=%d", err, completed, done)
			}
		})
	}
}

type round1HomeDispatcher struct{ payload []byte }

func (d round1HomeDispatcher) HeartbeatOK() bool       { return true }
func (d round1HomeDispatcher) AbortAmbiguousDispatch() {}
func (d round1HomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	return d.payload, nil
}

func TestRound1HomeLegacyCodexStreaming(t *testing.T) {
	for _, support := range []string{"legacy", "true", "false"} {
		t.Run(support, func(t *testing.T) {
			bodies := make(chan []byte, 1)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				bodies <- b
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6-luna\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":\"gpt-6-luna\",\"output\":[]}}\n\n")
			}))
			defer s.Close()
			credential := &auth.Auth{ID: t.Name(), Provider: "codex", Prefix: "tenant", Attributes: map[string]string{"source": "config:codex[0]", "api_key": "home-key", "base_url": s.URL}}
			info := map[string]any{"id": "gpt-6-luna"}
			if support != "legacy" {
				info["support_configuration_update"] = support == "true"
			}
			wire, _ := json.Marshal(map[string]any{"model": "gpt-6-luna", "auth": credential, "model_info": info})
			m := auth.NewManager(nil, nil, nil)
			m.SetConfig(&config.Config{Home: config.HomeConfig{Enabled: true}, CodexKey: []config.CodexKey{{APIKey: "home-key", Prefix: "tenant", BaseURL: s.URL, Models: []config.CodexModel{{Name: "gpt-6-luna", SupportConfigurationUpdate: true}}}}})
			m.PublishHomeDispatch(round1HomeDispatcher{payload: wire}, executionregistry.New(), 1)
			m.RegisterExecutor(NewCodexExecutor(&config.Config{}))
			payload := []byte(`{"input":[{"type":"configuration_update","reasoning":{"effort":"high"}},{"role":"user","content":"hi"}]}`)
			result, err := m.ExecuteStream(t.Context(), []string{"codex"}, core.Request{Model: "tenant/gpt-6-luna", Payload: payload}, core.Options{SourceFormat: translator.FormatOpenAIResponse, Stream: true})
			if err != nil {
				t.Fatal(err)
			}
			for c := range result.Chunks {
				if c.Err != nil {
					t.Fatal(c.Err)
				}
			}
			b := <-bodies
			hasUpdate := false
			for _, item := range gjson.GetBytes(b, "input").Array() {
				if item.Get("type").String() == "configuration_update" {
					hasUpdate = true
				}
			}
			if hasUpdate != (support != "false") {
				t.Errorf("Home %s update behavior lost: %s", support, b)
			}
		})
	}
}
