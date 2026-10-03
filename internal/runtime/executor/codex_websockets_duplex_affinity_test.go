package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	translator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// The strict store lookup is covered in auth's tests. This real socket fixture
// proves the executor invokes that narrow contract before a follow-up write,
// with the actual account and final translated (append -> create) payload,
// or the unchanged raw response.steer control frame.
func TestCodexDuplexAffinityAdmissionBeforeWrite(t *testing.T) {
	for _, kind := range []string{"response.create", "response.append", "response.steer"} {
		for _, block := range []string{"known-b", "unknown", "expired", "composite", "known-a", "ordinary"} {
			t.Run(kind+"/"+block, func(t *testing.T) {
				allowed := block == "known-a" || block == "ordinary"
				var connections, followups, validations atomic.Int32
				serverDone := make(chan struct{}, 2)
				receipts := make(chan []byte, 2)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer func() { serverDone <- struct{}{} }()
					connections.Add(1)
					if r.Header.Get("Authorization") != "Bearer account-a" {
						t.Error("socket selected a different account")
					}
					conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
					if err != nil {
						t.Error(err)
						return
					}
					defer func() { _ = conn.Close() }()
					_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
					if _, _, err = conn.ReadMessage(); err != nil {
						t.Error(err)
						return
					}
					if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"first","model":"gpt-6-astra","output":[]}}`)); err != nil {
						t.Error(err)
						return
					}
					if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"first","model":"gpt-6-astra","output":[]}}`)); err != nil {
						t.Error(err)
						return
					}
					// Receipt barrier: the client must close a rejected socket without
					// transmitting the candidate frame. No sleep-based absence check.
					for {
						_, payload, errRead := conn.ReadMessage()
						if errRead != nil {
							return
						}
						followups.Add(1)
						receipts <- payload
						if !allowed {
							t.Errorf("rejected input reached upstream: %s", payload)
							return
						}
						if kind == "response.steer" {
							if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.steer.accepted","steer":{"id":"s1","previous_response_id":"first"}}`)); err != nil {
								t.Error(err)
								return
							}
						}
						if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.created","response":{"id":"second","model":"gpt-6-astra","output":[]}}`)); err != nil {
							t.Error(err)
							return
						}
						if err = conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"response.completed","response":{"id":"second","model":"gpt-6-astra","output":[]}}`)); err != nil {
							t.Error(err)
							return
						}
					}
				}))
				defer server.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				input := make(chan core.WebsocketInput, 1)
				ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
				exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{ResponseSteering: true}})
				exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
				candidate := &auth.Auth{ID: "A", Provider: "codex", Attributes: map[string]string{"api_key": "account-a", "base_url": server.URL, "websockets": "true"}}
				localCause := &auth.Error{Code: "compaction_affinity_conflict", Message: "signed input does not belong to socket A", HTTPStatus: http.StatusConflict}
				var submitted []byte
				opts := core.Options{SourceFormat: translator.FromString("codex"), Metadata: map[string]any{
					core.ExecutionSessionMetadataKey: t.Name(),
					core.CompactionAffinityValidatorMetadataKey: func(actualID string, payload []byte) error {
						validations.Add(1)
						if actualID != "A" {
							t.Errorf("callback account = %s", actualID)
						}
						if kind == "response.steer" {
							if string(payload) != string(submitted) || gjson.GetBytes(payload, "type").String() != kind || gjson.GetBytes(payload, "model").Exists() {
								t.Errorf("callback did not see unchanged raw steer: %s", payload)
							}
						} else if gjson.GetBytes(payload, "type").String() != "response.create" || gjson.GetBytes(payload, "model").String() == "" {
							t.Errorf("callback did not see prepared submission: %s", payload)
						}
						if allowed {
							return nil
						}
						return localCause
					},
				}}
				result, err := exec.ExecuteStream(ctx, candidate, core.Request{Model: "gpt-6-astra", Payload: []byte(`{"model":"gpt-6-astra","input":[]}`)}, opts)
				if err != nil {
					t.Fatal(err)
				}
				var streamErr error
				completed := false
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						streamErr = chunk.Err
						continue
					}
					if gjson.GetBytes(chunk.Payload, "type").String() != "response.completed" {
						continue
					}
					if gjson.GetBytes(chunk.Payload, "response.id").String() == "first" {
						items := fmt.Sprintf(`[{"type":"compaction","encrypted_content":%q}]`, block)
						if block == "composite" {
							items = `[{"type":"compaction","encrypted_content":"known-a"},{"type":"compaction","encrypted_content":"known-b"}]`
						}
						if block == "ordinary" {
							items = `[{"type":"function_call_output","call_id":"call-1","output":"ok"}]`
						}
						submitted = []byte(fmt.Sprintf(`{"type":%q,"input":%s}`, kind, items))
						if kind == "response.steer" {
							submitted = []byte(fmt.Sprintf(`{"type":%q,"previous_response_id":"first","input":%s,"unknown_field":{"keep":"raw"}}`, kind, items))
						}
						input <- core.WebsocketInput{Payload: submitted}
					} else {
						completed = true
						cancel()
					}
				}
				select {
				case <-serverDone:
				case <-time.After(3 * time.Second):
					t.Fatal("socket cleanup did not reach receipt barrier")
				}
				if connections.Load() != 1 || validations.Load() != 1 {
					t.Fatalf("connections=%d validations=%d", connections.Load(), validations.Load())
				}
				if allowed {
					if streamErr != nil || !completed || followups.Load() != 1 {
						t.Fatalf("allowed input: err=%v completed=%v writes=%d", streamErr, completed, followups.Load())
					}
					select {
					case payload := <-receipts:
						if kind == "response.steer" && string(payload) != string(submitted) {
							t.Fatalf("allowed steer changed before upstream write: %s", payload)
						}
					default:
						t.Fatal("allowed follow-up has no upstream receipt")
					}
				} else {
					var local *codexDuplexAffinityError
					if !errors.As(streamErr, &local) || !errors.Is(streamErr, localCause) || local.StatusCode() != http.StatusConflict || !local.IsRequestScoped() {
						t.Fatalf("rejection lost local type or cause: %v", streamErr)
					}
					if followups.Load() != 0 || len(receipts) != 0 {
						t.Fatal("rejected follow-up was written upstream")
					}
				}
			})
		}
	}
}

func TestCodexDuplexSteerAffinityValidatorPreservesLocalError(t *testing.T) {
	payload := []byte(`{"type":"response.steer","previous_response_id":"first","input":[{"type":"compaction","encrypted_content":"known-b"}],"unknown_field":"untouched"}`)
	original := string(payload)
	cause := &auth.Error{Code: "compaction_affinity_conflict", Message: "wrong signer", HTTPStatus: http.StatusConflict}
	calls := 0
	opts := core.Options{Metadata: map[string]any{
		core.CompactionAffinityValidatorMetadataKey: func(actualID string, actualPayload []byte) error {
			calls++
			if actualID != "A" || string(actualPayload) != original {
				t.Fatalf("validator input changed: account=%s payload=%s", actualID, actualPayload)
			}
			return cause
		},
	}}
	err := validateCodexDuplexCompaction(opts, "A", payload)
	var local *codexDuplexAffinityError
	var typedCause *auth.Error
	if !errors.As(err, &local) || !errors.As(err, &typedCause) || typedCause != cause || !errors.Is(err, cause) || local.StatusCode() != http.StatusConflict || !local.IsRequestScoped() {
		t.Fatalf("validator lost local type, status, scope or cause: %v", err)
	}
	if calls != 1 || string(payload) != original {
		t.Fatalf("validator calls=%d payload=%s", calls, payload)
	}
}

func TestCodexDuplexAffinityAbsentCallback(t *testing.T) {
	if err := validateCodexDuplexCompaction(core.Options{}, "A", []byte(`{"input":[{"type":"compaction","encrypted_content":"unknown"}]}`)); err != nil {
		t.Fatalf("no-affinity origin changed behavior: %v", err)
	}
}
