package handlers_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// Recorded catch: PR #174 r7 S-1. Exercise real WebSocket reads through the
// conductor: model-only output is private until non-stream completion, whereas
// server-side tool execution must never be replayed on another credential.
func TestCodexNonStreamModelOnlyFailover(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []string
		work   bool
	}{
		{name: "text", frames: []string{`{"type":"response.output_text.delta","delta":"hello"}`}},
		{name: "reasoning", frames: []string{`{"type":"response.reasoning_summary_text.delta","delta":"thinking"}`}},
		{name: "function_call", frames: []string{`{"type":"response.output_item.added","item":{"type":"function_call","id":"fc","name":"lookup","arguments":""}}`}},
		{name: "custom_tool_call", frames: []string{`{"type":"response.output_item.added","item":{"type":"custom_tool_call","id":"ct","name":"patch","input":""}}`}},
		{name: "function_arguments", frames: []string{`{"type":"response.output_item.added","item":{"type":"function_call","id":"fc","name":"lookup","arguments":""}}`, `{"type":"response.function_call_arguments.delta","item_id":"fc","delta":"{}"}`}},
		{name: "custom_input", frames: []string{`{"type":"response.output_item.added","item":{"type":"custom_tool_call","id":"ct","name":"patch","input":""}}`, `{"type":"response.custom_tool_call_input.delta","item_id":"ct","delta":"patch"}`}},
		{name: "web_search", frames: []string{`{"type":"response.output_item.added","item":{"type":"web_search_call","id":"ws","status":"in_progress"}}`}, work: true},
		{name: "mcp", frames: []string{`{"type":"response.output_item.added","item":{"type":"mcp_call","id":"mcp","status":"in_progress"}}`}, work: true},
	} {
		for _, cut := range []string{"remove", "drop", "server_error"} {
			t.Run(tc.name+"/"+cut, func(t *testing.T) {
				cfg := &config.Config{}
				manager := coreauth.NewManager(nil, &coreauth.FillFirstSelector{}, nil)
				manager.SetRetryConfig(0, 0, 2)
				firstID := t.Name() + "account-a"
				consumed := make(chan struct{})
				var once sync.Once
				var mu sync.Mutex
				var attempts []string
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					if _, _, err := conn.ReadMessage(); err != nil {
						t.Error(err)
						return
					}
					account := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					mu.Lock()
					attempts = append(attempts, account)
					mu.Unlock()
					write := func(frame string) bool {
						if err := conn.WriteMessage(websocket.TextMessage, []byte(frame)); err != nil {
							t.Error(err)
							return false
						}
						return true
					}
					if account == "account-b" {
						write(`{"type":"response.completed","response":{"id":"resp-healthy","model":"gpt-6-astra","status":"completed","output":[],"usage":{"input_tokens":0,"output_tokens":0}}}`)
						return
					}
					if !write(`{"type":"response.created","response":{"id":"resp-a","model":"gpt-6-astra"}}`) {
						return
					}
					for _, frame := range tc.frames {
						if !write(frame) {
							return
						}
					}
					// Cut only after Execute has consumed the last model/work frame.
					<-consumed
					switch cut {
					case "remove":
						_, _, _ = conn.ReadMessage()
					case "server_error":
						write(`{"type":"response.failed","response":{"id":"resp-a","model":"gpt-6-astra","error":{"type":"server_error","code":"server_error","message":"upstream failed"}}}`)
					}
				}))
				defer upstream.Close()
				exec := runtimeexecutor.NewCodexWebsocketsExecutor(cfg)
				manager.RegisterExecutor(exec)
				defer exec.CloseExecutionSession(coreauth.CloseAllExecutionSessionsID)
				for i, account := range []string{"account-a", "account-b"} {
					id := t.Name() + account
					_, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": account, "base_url": upstream.URL, "websockets": "true", "priority": fmt.Sprint(100 - i)}})
					if err != nil {
						t.Fatal(err)
					}
					registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-6-astra"}})
					defer registry.GetGlobalRegistry().UnregisterClient(id)
				}
				lastType := gjson.Get(tc.frames[len(tc.frames)-1], "type").String()
				opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAIResponse, Metadata: map[string]any{coreexecutor.ExecutionSessionMetadataKey: t.Name()}}
				opts.WebSocketResponseObserver = func(_ context.Context, event coreexecutor.WebSocketResponseEvent) {
					if event.AuthID == firstID && event.EventType == lastType {
						once.Do(func() {
							if cut == "remove" {
								manager.Remove(context.Background(), firstID)
								runtimeexecutor.CloseCodexWebsocketSessionsForAuthID(firstID, "auth_removed")
							}
							close(consumed)
						})
					}
				}
				resp, err := manager.Execute(context.Background(), []string{"codex"}, coreexecutor.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","input":"proof"}`)}, opts)
				mu.Lock()
				got := append([]string(nil), attempts...)
				mu.Unlock()
				var stop interface{ IsRequestStop() bool }
				stopped := errors.As(err, &stop) && stop.IsRequestStop()
				auth, exists := manager.GetByID(firstID)
				cooled := false
				if exists {
					cooled = auth.Unavailable || !auth.NextRetryAfter.IsZero()
					for _, state := range auth.ModelStates {
						cooled = cooled || state.Unavailable || !state.NextRetryAfter.IsZero()
					}
				}
				t.Logf("S1 shape=%s cut=%s attempts=%v stop=%t cooled=%t error=%v", tc.name, cut, got, stopped, cooled, err)
				want := []string{"account-a", "account-b"}
				if tc.work {
					want = []string{"account-a"}
					if err == nil || !stopped || len(resp.Payload) != 0 {
						t.Errorf("server work must stop: err=%v body=%s", err, resp.Payload)
					}
				} else {
					if err != nil || !strings.Contains(string(resp.Payload), "resp-healthy") {
						t.Errorf("model-only output must fail over: err=%v body=%s", err, resp.Payload)
					}
					if cut == "server_error" && !cooled {
						t.Error("server_error must cool A")
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("attempts=%v want=%v", got, want)
				}
				if cut == "remove" && exists {
					t.Error("removed credential restored")
				}
			})
		}
	}
}
