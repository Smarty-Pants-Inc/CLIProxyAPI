package executor

import (
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
	"github.com/tidwall/gjson"
)

// Reproduce the refused Opus turn through the real Messages handler, auth
// manager and Claude executor. A listed fallback must never reach the client.
func TestClaudeModelMismatchAuthFailover(t *testing.T) {
	const model = "claude-opus-5-5"
	const fallback = "claude-opus-4-8"
	for _, stream := range []bool{false, true} {
		for _, oauth := range []bool{false, true} {
			for _, tc := range []struct {
				name           string
				models         []string
				maxCredentials int
				requestRetry   int
				disableCooling bool
				wantStatus     int
				wantSeats      []int
			}{
				{name: "exact", models: []string{model, fallback, fallback}, wantStatus: 200, wantSeats: []int{0}},
				{name: "fallback-then-exact", models: []string{fallback, model, model}, wantStatus: 200, wantSeats: []int{0, 1}},
				{name: "missing-then-exact", models: []string{"", model, model}, wantStatus: 200, wantSeats: []int{0, 1}},
				{name: "all-mismatch", models: []string{fallback, fallback, fallback}, wantStatus: 502, wantSeats: []int{0, 1, 2}},
				{name: "credential-cap", models: []string{fallback, fallback, model}, maxCredentials: 2, wantStatus: 502, wantSeats: []int{0, 1}},
				{name: "one-additional-round", models: []string{fallback, fallback, fallback}, requestRetry: 1, disableCooling: true, wantStatus: 502, wantSeats: []int{0, 1, 2, 0, 1, 2}},
			} {
				t.Run(fmt.Sprintf("stream=%t/oauth=%t/%s", stream, oauth, tc.name), func(t *testing.T) {
					cfg := &config.Config{}
					manager := auth.NewManager(nil, &auth.FillFirstSelector{}, nil)
					manager.SetConfig(cfg)
					manager.SetRetryConfig(tc.requestRetry, 0, tc.maxCredentials)
					manager.RegisterExecutor(NewClaudeExecutor(cfg))
					var mu sync.Mutex
					var seats []int
					for seat, responseModel := range tc.models {
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							body, errRead := io.ReadAll(r.Body)
							if errRead != nil {
								t.Error(errRead)
								return
							}
							if got := gjson.GetBytes(body, "model").String(); got != model {
								t.Errorf("seat %d received model %q, want unchanged %q", seat, got, model)
							}
							mu.Lock()
							seats = append(seats, seat)
							mu.Unlock()
							text := "VERIFIED_SUCCESS"
							if responseModel != model {
								text = "UNVERIFIED_MUST_NOT_LEAK"
							}
							message := map[string]any{"id": "msg_fixture", "type": "message", "role": "assistant", "content": []any{}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
							if responseModel != "" {
								message["model"] = responseModel
							}
							if stream {
								w.Header().Set("Content-Type", "text/event-stream")
								emit := func(event any) {
									data, _ := json.Marshal(event)
									fmt.Fprintf(w, "event: %s\ndata: %s\n\n", gjson.GetBytes(data, "type").String(), data)
								}
								emit(map[string]any{"type": "ping"})
								emit(map[string]any{"type": "message_start", "message": message})
								emit(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": text}})
								emit(map[string]any{"type": "message_delta", "delta": map[string]string{"stop_reason": "end_turn"}, "usage": map[string]int{"output_tokens": 1}})
								emit(map[string]any{"type": "message_stop"})
							} else {
								w.Header().Set("Content-Type", "application/json")
								message["content"] = []any{map[string]string{"type": "text", "text": text}}
								message["stop_reason"] = "end_turn"
								_ = json.NewEncoder(w).Encode(message)
							}
						}))
						t.Cleanup(server.Close)
						id := fmt.Sprintf("claude-mismatch-%d-%s", seat, t.Name())
						credential := &auth.Auth{ID: id, Provider: "claude", Status: auth.StatusActive,
							Attributes: map[string]string{"api_key": "synthetic", "base_url": server.URL},
							Metadata:   map[string]any{"disable_cooling": tc.disableCooling},
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
					payload := fmt.Sprintf(`{"model":%q,"fallbacks":[{"model":%q}],"max_tokens":32,"stream":%t,"messages":[{"role":"user","content":"reply OK"}]}`, model, fallback, stream)
					req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(payload))
					req.Header.Set("Content-Type", "application/json")
					recorder := httptest.NewRecorder()
					router.ServeHTTP(recorder, req)
					body := recorder.Body.String()
					if recorder.Code != tc.wantStatus {
						t.Errorf("HTTP status = %d, want %d; body=%s", recorder.Code, tc.wantStatus, body)
					}
					mu.Lock()
					gotSeats := append([]int(nil), seats...)
					mu.Unlock()
					if !reflect.DeepEqual(gotSeats, tc.wantSeats) {
						t.Errorf("auth attempts = %v, want %v", gotSeats, tc.wantSeats)
					}
					t.Logf("measured auth attempts=%v (request-retry=%d max-retry-credentials=%d)", gotSeats, tc.requestRetry, tc.maxCredentials)
					if strings.Contains(body, "UNVERIFIED_MUST_NOT_LEAK") || strings.Contains(body, fallback) {
						t.Errorf("unverified fallback output escaped: %s", body)
					}
					if tc.wantStatus == http.StatusOK {
						if !strings.Contains(body, model) || !strings.Contains(body, "VERIFIED_SUCCESS") {
							t.Errorf("verified response missing: %s", body)
						}
						if stream && (strings.Count(body, "event: message_start\n") != 1 || strings.Count(body, "event: ping\n") != 1) {
							t.Errorf("unverified stream preamble escaped: %s", body)
						}
					} else if !strings.Contains(body, "model_mismatch") || strings.Contains(body, "event:") {
						t.Errorf("want final 502 model_mismatch without SSE output: %s", body)
					}
				})
			}
		}
	}
}
