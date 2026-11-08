package executor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	claudehandlers "github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// PR #197: exercise the Messages handler, manager and executor together. Declines
// remain ordinary responses on the pinned model; mismatches neither rotate nor
// cool credentials, even with cooling and an extra retry round enabled.
func TestClaudePinnedModelPolicy(t *testing.T) {
	const model = "claude-opus-5-5"
	const fallback = "claude-opus-4-8"
	for _, stream := range []bool{false, true} {
		for _, oauth := range []bool{false, true} {
			for _, tc := range []struct {
				name, fallbacks, responseModel string
				wantStatus                     int
			}{
				{name: "refusal-array", fallbacks: `,"fallbacks":[{"model":"claude-opus-4-8"}]`, responseModel: model, wantStatus: 200},
				{name: "refusal-default", fallbacks: `,"fallbacks":"default"`, responseModel: model, wantStatus: 200},
				{name: "refusal-no-fallbacks", responseModel: model, wantStatus: 200},
				{name: "mismatch", fallbacks: `,"fallbacks":[{"model":"claude-opus-4-8"}]`, responseModel: fallback, wantStatus: 502},
				{name: "missing-model", responseModel: "", wantStatus: 502},
			} {
				t.Run(fmt.Sprintf("stream=%t/oauth=%t/%s", stream, oauth, tc.name), func(t *testing.T) {
					cfg := &config.Config{}
					manager := auth.NewManager(nil, &auth.FillFirstSelector{}, nil)
					manager.SetConfig(cfg)
					manager.SetRetryConfig(1, 0, 0)
					manager.RegisterExecutor(NewClaudeExecutor(cfg))
					var mu sync.Mutex
					var seats []int
					for seat := range 3 {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							body, errRead := io.ReadAll(r.Body)
							if errRead != nil {
								t.Error(errRead)
								return
							}
							if got := gjson.GetBytes(body, "model").String(); got != model {
								t.Errorf("seat %d received model %q, want unchanged %q", seat, got, model)
							}
							if gjson.GetBytes(body, "fallbacks").Exists() {
								t.Errorf("seat %d received server-side fallbacks: %s", seat, body)
							}
							mu.Lock()
							seats = append(seats, seat)
							attempt := len(seats)
							mu.Unlock()
							responseModel := tc.responseModel
							// The next independent request must reuse the first seat after
							// a mismatch, without disabling or waiting out cooling.
							if attempt > 1 {
								responseModel = model
							}
							text := "VERIFIED_REFUSAL"
							if responseModel != model {
								text = "UNVERIFIED_MUST_NOT_LEAK"
							}
							writeClaudePinnedResponse(w, stream, responseModel, text)
						}))
						t.Cleanup(server.Close)
						id := fmt.Sprintf("claude-pinned-%d-%s", seat, t.Name())
						credential := &auth.Auth{ID: id, Provider: "claude", Status: auth.StatusActive,
							Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL},
							Metadata:   map[string]any{"disable_cooling": false},
						}
						if oauth {
							credential.Attributes["api_key"] = "sk-ant-oat-synthetic"
							for key, value := range claudeOAuthCancellationTestMetadata() {
								credential.Metadata[key] = value
							}
						}
						reg := registry.GetGlobalRegistry()
						reg.RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
						t.Cleanup(func() { reg.UnregisterClient(id) })
						if _, errRegister := manager.Register(t.Context(), credential); errRegister != nil {
							t.Fatal(errRegister)
						}
					}
					gin.SetMode(gin.TestMode)
					h := claudehandlers.NewClaudeCodeAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager))
					router := gin.New()
					router.POST("/v1/messages", h.ClaudeMessages)
					payload := fmt.Sprintf(`{"model":%q%s,"max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"reply OK"}]}`, model, tc.fallbacks, stream)
					call := func(wantStatus int) {
						t.Helper()
						req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(payload))
						req.Header.Set("Content-Type", "application/json")
						recorder := httptest.NewRecorder()
						router.ServeHTTP(recorder, req)
						body := recorder.Body.String()
						if recorder.Code != wantStatus {
							t.Errorf("HTTP status = %d, want %d; body=%s", recorder.Code, wantStatus, body)
						}
						if strings.Contains(body, "UNVERIFIED_MUST_NOT_LEAK") || strings.Contains(body, fallback) {
							t.Errorf("unverified fallback output escaped: %s", body)
						}
						if wantStatus == http.StatusOK {
							if !strings.Contains(body, model) || !strings.Contains(body, "VERIFIED_REFUSAL") || !strings.Contains(body, `"stop_reason":"refusal"`) {
								t.Errorf("normal refusal response missing: %s", body)
							}
							if stream && strings.Count(body, "event: message_start\n") != 1 {
								t.Errorf("want exactly one verified message_start: %s", body)
							}
						} else if !strings.Contains(body, "model_mismatch") || strings.Contains(body, "event:") {
							t.Errorf("want final 502 model_mismatch without SSE output: %s", body)
						}
					}
					call(tc.wantStatus)
					mu.Lock()
					gotSeats := append([]int(nil), seats...)
					mu.Unlock()
					if !reflect.DeepEqual(gotSeats, []int{0}) {
						t.Errorf("auth attempts = %v, want [0] (no failover or retry)", gotSeats)
					}
					for _, credential := range manager.List() {
						if credential.Unavailable || !credential.NextRetryAfter.IsZero() || credential.Quota.Exceeded {
							t.Errorf("credential cooled after request: %s", credential.ID)
						}
						for name, state := range credential.ModelStates {
							if state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded {
								t.Errorf("credential %s model %s cooled after request", credential.ID, name)
							}
						}
					}
					if tc.wantStatus != http.StatusOK {
						call(http.StatusOK)
						mu.Lock()
						gotSeats = append([]int(nil), seats...)
						mu.Unlock()
						if !reflect.DeepEqual(gotSeats, []int{0, 0}) {
							t.Errorf("mismatching seat not immediately reusable: attempts=%v, want [0 0]", gotSeats)
						}
					}
				})
			}
		}
	}
}

func writeClaudePinnedResponse(w http.ResponseWriter, stream bool, model, text string) {
	message := map[string]any{"id": "msg_pinned", "type": "message", "role": "assistant", "content": []any{}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
	if model != "" {
		message["model"] = model
	}
	if stream {
		w.Header().Set("Content-Type", "text/event-stream")
		emit := func(event any) {
			data, _ := json.Marshal(event)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.GetBytes(data, "type").String(), data)
		}
		emit(map[string]any{"type": "ping"})
		emit(map[string]any{"type": "message_start", "message": message})
		emit(map[string]any{"type": "content_block_start", "index": 0, "content_block": map[string]string{"type": "text", "text": ""}})
		emit(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": text}})
		emit(map[string]any{"type": "content_block_stop", "index": 0})
		emit(map[string]any{"type": "message_delta", "delta": map[string]string{"stop_reason": "refusal"}, "usage": map[string]int{"output_tokens": 1}})
		emit(map[string]any{"type": "message_stop"})
	} else {
		w.Header().Set("Content-Type", "application/json")
		message["content"] = []any{map[string]string{"type": "text", "text": text}}
		message["stop_reason"] = "refusal"
		_ = json.NewEncoder(w).Encode(message)
	}
}

// Capture exact upstream bytes, not just decoded fields: stripping the top-level
// dispatch option must preserve nested lookalikes, fallback credits and all
// other caller data. Requests without the option must not be reserialized.
func TestClaudePinnedModelRequestBytes(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, field := range []string{"", `,"fallbacks":[{"model":"claude-opus-4-8"}]`, `,"fallbacks":"default"`, `,"fallbacks":null`, `,"fallbacks":[]`} {
			t.Run(fmt.Sprintf("stream=%t/field=%s", stream, field), func(t *testing.T) {
				var seen []byte
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var err error
					seen, err = io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
					}
					writeClaudePinnedResponse(w, stream, "claude-opus-5-5", "REFUSAL")
				}))
				t.Cleanup(server.Close)
				// A caller-owned API-key body avoids unrelated OAuth identity and
				// cache injection; whitespace and escapes are intentionally noncanonical.
				base := fmt.Sprintf("{\n  \"model\":\"claude-opus-5-5\", \"max_tokens\":32,\"stream\":%t,\"system\":[{\"type\":\"text\",\"text\":\"caller\\u0020system\",\"cache_control\":{\"type\":\"ephemeral\"}}],\"messages\":[{\"role\":\"user\",\"content\":\"reply OK\"}],\"metadata\":{\"fallbacks\":\"nested-must-stay\"},\"fallback_credit_token\":\"keep-credit\"", stream)
				payload := []byte(base + field + "\n}")
				want := []byte(base + "\n}")
				credential := &auth.Auth{ID: t.Name(), Provider: "claude", Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL}}
				req := core.Request{Model: "claude-opus-5-5", Payload: payload}
				opts := core.Options{SourceFormat: translator.FormatClaude, Stream: stream}
				e := NewClaudeExecutor(&config.Config{})
				if stream {
					result, err := e.ExecuteStream(t.Context(), credential, req, opts)
					if err != nil {
						t.Fatal(err)
					}
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatal(chunk.Err)
						}
					}
				} else if _, err := e.Execute(t.Context(), credential, req, opts); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(seen, want) {
					t.Fatalf("upstream changed beyond top-level fallbacks removal:\n got: %s\nwant: %s", seen, want)
				}
			})
		}
	}
}
