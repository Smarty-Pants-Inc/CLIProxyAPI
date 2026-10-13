package handlers_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type nativeRound1Selector struct{ preferred string }

func (s *nativeRound1Selector) Pick(_ context.Context, _, _ string, _ coreexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	for _, auth := range auths {
		if auth.ID == s.preferred {
			return auth, nil
		}
	}
	return (&coreauth.FillFirstSelector{}).Pick(context.Background(), "", "", coreexecutor.Options{}, auths)
}

type nativeRound1Writer struct {
	*httptest.ResponseRecorder
	onSigned func()
	seen     bool
}

func (w *nativeRound1Writer) Write(p []byte) (int, error) {
	if !w.seen && bytes.Contains(p, []byte("native-http-")) {
		w.seen = true
		w.onSigned()
	}
	return w.ResponseRecorder.Write(p)
}

// Uses the real native /v1/messages handler AND ClaudeExecutor, not a fixture
// executor returning Responses-shaped capsules. The only fake is Anthropic's
// network endpoint, with safe credential IDs A/B and genuine native wire shapes.
func TestNativeMessagesCompactionRound1BeforeDeliveryAndFirstReplay(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, production := range []string{"nonstream", "stream-complete-start", "stream-skeleton-deltas"} {
		for _, restart := range []bool{false, true} {
			name := production + "/fresh"
			if restart {
				name = production + "/restart-before-first-replay"
			}
			t.Run(name, func(t *testing.T) {
				const model = "claude-opus-5"
				firstID, secondID := "native-round1-"+t.Name()+"-A", "native-round1-"+t.Name()+"-B"
				var callsA, callsB atomic.Int32
				var failA atomic.Bool
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/v1/messages" {
						t.Errorf("unexpected native endpoint: %s", r.URL.Path)
					}
					key := r.Header.Get("X-Api-Key")
					if key == "" {
						key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					}
					switch key {
					case "native-A":
						callsA.Add(1)
						if failA.Load() {
							w.WriteHeader(http.StatusServiceUnavailable)
							_, _ = w.Write([]byte(`{"error":{"type":"overloaded_error","message":"forced A 503"}}`))
							return
						}
					case "native-B":
						callsB.Add(1)
					default:
						t.Errorf("unexpected native fixture credential")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if production == "nonstream" {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"id":"msg_native","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"compaction","content":"native-http-signed-summary"}],"stop_reason":"compaction","usage":{"input_tokens":20,"output_tokens":5}}`))
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					writeEvent := func(name, data string) {
						_, _ = w.Write([]byte("event: " + name + "\ndata: " + data + "\n\n"))
						w.(http.Flusher).Flush()
					}
					writeEvent("message_start", `{"type":"message_start","message":{"id":"msg_native","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":20,"output_tokens":0}}}`)
					block := `{"type":"compaction","content":"native-http-signed-summary"}`
					if production == "stream-skeleton-deltas" {
						block = `{"type":"compaction","content":""}`
					}
					writeEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":`+block+`}`)
					if production == "stream-skeleton-deltas" {
						writeEvent("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"native-http-"}}`)
						writeEvent("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"signed-summary"}}`)
					}
					writeEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)
					writeEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"compaction"},"usage":{"output_tokens":5}}`)
					writeEvent("message_stop", `{"type":"message_stop"}`)
				}))
				defer upstream.Close()
				statePath := filepath.Join(t.TempDir(), "affinity.state")
				selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &nativeRound1Selector{preferred: firstID}, StatePath: statePath})
				defer selector.Stop()
				newRouter := func(affinity *coreauth.SessionAffinitySelector) *gin.Engine {
					manager := coreauth.NewManager(nil, affinity, nil)
					manager.SetRetryConfig(0, 0, 0)
					manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(&internalconfig.Config{}))
					for i, id := range []string{firstID, secondID} {
						key := "native-A"
						if i == 1 {
							key = "native-B"
						}
						if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "claude", Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": key, "base_url": upstream.URL}}); err != nil {
							t.Fatal(err)
						}
						registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
					}
					base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
					handler := claude.NewClaudeCodeAPIHandler(base)
					router := gin.New()
					router.POST("/v1/messages", handler.ClaudeMessages)
					return router
				}
				defer registry.GetGlobalRegistry().UnregisterClient(firstID)
				defer registry.GetGlobalRegistry().UnregisterClient(secondID)
				router := newRouter(selector)
				stream := "false"
				if production != "nonstream" {
					stream = "true"
				}
				body := `{"model":"claude-opus-5","max_tokens":100,"compaction":{"type":"summarize"},"messages":[{"role":"user","content":"compact this"}],"stream":` + stream + `}`
				request := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Session-Id", "native-http-conversation")
				writer := &nativeRound1Writer{ResponseRecorder: httptest.NewRecorder(), onSigned: func() {
					// The first actual client Write must already permit a fresh
					// request, without session identity or inherited metadata.
					failA.Store(true)
					replaySelector := selector
					if restart {
						selector.Stop()
						replaySelector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &nativeRound1Selector{preferred: secondID}, StatePath: statePath})
						defer replaySelector.Stop()
					}
					replayRouter := newRouter(replaySelector)
					replay := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"claude-opus-5","max_tokens":100,"messages":[{"role":"assistant","content":[{ "content" : "native-http-signed-summary", "type" : "compaction" }]},{"role":"user","content":"continue"}]}`))
					replay.Header.Set("Content-Type", "application/json")
					response := httptest.NewRecorder()
					replayRouter.ServeHTTP(response, replay)
					if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "forced A 503") {
						t.Errorf("first native replay: status=%d body=%s", response.Code, response.Body)
					}
					if callsA.Load() != 2 || callsB.Load() != 0 {
						t.Errorf("native execution counts A=%d B=%d; want A production+replay, zero B", callsA.Load(), callsB.Load())
					}
				}}
				router.ServeHTTP(writer, request)
				if writer.Code != http.StatusOK || !writer.seen {
					t.Fatalf("native production not delivered: status=%d seen=%v body=%s", writer.Code, writer.seen, writer.Body)
				}
				if production != "nonstream" && !strings.Contains(writer.Body.String(), "event: content_block_stop") {
					t.Fatalf("native events lost: %s", writer.Body)
				}
			})
		}
	}
}
