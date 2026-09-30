package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

type round3SocketSnapshot struct {
	Version int `json:"version"`
	Groups []struct {
		AuthID string `json:"auth_id"`
		ExpiresAt time.Time `json:"expires_at"`
		Aliases []string `json:"aliases"`
		Protected bool `json:"protected"`
	} `json:"groups"`
}

func round3ReadSocketSnapshot(t *testing.T, path string) round3SocketSnapshot {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var snapshot round3SocketSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil { t.Fatal(err) }
	return snapshot
}

// Actual socket production and follow-up admission, with no validator stub and
// no capsule echo after production. SetTTL + GetAndRefresh change the expiration
// of already-produced evidence; a shifted real snapshot advances the replay
// clock across the original expiry without a multi-hour sleep.
func TestCodexDuplexRetentionRound3ActualSocket(t *testing.T) {
	for _, action := range []string{"response.create", "response.append", "response.steer"} {
		t.Run(action, func(t *testing.T) {
			id, model := t.Name()+"-A", "retention-socket-model"
			var connections, followups atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil { t.Error(err); return }
				defer conn.Close()
				n := connections.Add(1)
				_ = conn.SetReadDeadline(time.Now().Add(10*time.Second))
				if _, _, err := conn.ReadMessage(); err != nil { return }
				write := func(payload string) bool { return conn.WriteMessage(websocket.TextMessage, []byte(payload)) == nil }
				output := `[]`
				if n == 1 { output = `[{"type":"compaction","encrypted_content":"socket-retention-produced"}]` }
				if !write(`{"type":"response.created","response":{"id":"first","model":"retention-socket-model","output":[]}}`) ||
					!write(`{"type":"response.completed","response":{"id":"first","model":"retention-socket-model","output":`+output+`}}`) { return }
				if n == 1 {
					_, payload, err := conn.ReadMessage()
					if err != nil { return }
					followups.Add(1)
					wantType := "response.create"
					if action == "response.steer" { wantType = action }
					if gjson.GetBytes(payload, "type").String() != wantType || !strings.Contains(string(payload), "socket-retention-produced") {
						t.Errorf("follow-up wire=%s", payload)
						return
					}
					if action == "response.steer" && !write(`{"type":"response.steer.accepted","steer":{"id":"s1","previous_response_id":"first"}}`) { return }
					if !write(`{"type":"response.created","response":{"id":"second","model":"retention-socket-model","output":[]}}`) ||
						!write(`{"type":"response.completed","response":{"id":"second","model":"retention-socket-model","output":[]}}`) { return }
				}
				_, _, _ = conn.ReadMessage()
			}))
			defer server.Close()
			cfg := &config.Config{}
			cfg.Codex.ResponseSteering, cfg.CodexResponseSteering = true, true
			path := filepath.Join(t.TempDir(), "affinity.state")
			origin := auth.NewSessionAffinitySelectorWithConfig(auth.SessionAffinityConfig{StatePath: path})
			defer origin.Stop()
			origin.Cache().Stop()
			newManager := func(selector *auth.SessionAffinitySelector) *auth.Manager {
				m := auth.NewManager(nil, selector, nil)
				m.SetConfig(cfg)
				m.SetRetryConfig(0, 0, 0)
				m.RegisterExecutor(NewCodexAutoExecutor(cfg))
				_, err := m.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key":"test-key", "base_url":server.URL, "websockets":"true"}})
				if err != nil { t.Fatal(err) }
				return m
			}
			manager := newManager(origin)
			registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID:model}})
			defer registry.GetGlobalRegistry().UnregisterClient(id)
			run := func(m *auth.Manager, session, capsule string, produce bool) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				input := make(chan core.WebsocketInput, 1)
				ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
				items := `[]`
				if capsule != "" { items = `[{"type":"compaction","encrypted_content":"`+capsule+`"}]` }
				payload := []byte(`{"model":"`+model+`","input":`+items+`}`)
				stream, err := m.ExecuteStream(ctx, []string{"codex"}, core.Request{Model:model, Payload:payload}, core.Options{SourceFormat:translator.FormatCodex, OriginalRequest:payload, Metadata:map[string]any{core.ExecutionSessionMetadataKey:session}})
				if err != nil { t.Fatalf("actual socket replay: %v", err) }
				completed := 0
				for chunk := range stream.Chunks {
					if chunk.Err != nil { t.Fatalf("socket stream: %v", chunk.Err) }
					if gjson.GetBytes(chunk.Payload,"type").String() != "response.completed" { continue }
					completed++
					if !produce || completed == 2 { cancel(); break }
					// Simulate t=5h: this signer has one hour remaining, and
					// every future admission must restore the full six hours.
					snapshot := round3ReadSocketSnapshot(t, path)
					origin.Cache().SetTTL(time.Hour)
					signers := 0
					for _, group := range snapshot.Groups {
						for _, alias := range group.Aliases {
							if strings.HasPrefix(alias,"compaction:") {
								if _, ok := origin.Cache().GetAndRefresh(alias); !ok { t.Fatal("produced signer missing") }
								signers++
							}
						}
					}
					if signers != 1 { t.Fatalf("produced signer groups=%d",signers) }
					origin.Cache().SetTTL(6*time.Hour)
					input <- core.WebsocketInput{Payload:[]byte(fmt.Sprintf(`{"type":%q,"previous_response_id":"first","input":[{"type":"compaction","encrypted_content":"socket-retention-produced"}]}`,action))}
				}
				for range stream.Chunks {}
				want := 1
				if produce { want = 2 }
				if completed != want { t.Fatalf("completed=%d want=%d",completed,want) }
			}
			run(manager,t.Name()+"-initial","",true)
			if followups.Load()!=1 { t.Fatalf("follow-up writes=%d",followups.Load()) }
			// Advance two hours in the persisted clock. The old one-hour
			// deadline is now past; only successful follow-up admission can
			// leave live evidence. All later upstream output is ordinary.
			snapshot := round3ReadSocketSnapshot(t,path)
			for i := range snapshot.Groups { snapshot.Groups[i].ExpiresAt = snapshot.Groups[i].ExpiresAt.Add(-2*time.Hour) }
			data, err := json.Marshal(snapshot)
			if err != nil { t.Fatal(err) }
			shiftedPath := filepath.Join(t.TempDir(),"shifted-affinity.state")
			if err := os.WriteFile(shiftedPath,data,0o600); err != nil { t.Fatal(err) }
			restored := auth.NewSessionAffinitySelectorWithConfig(auth.SessionAffinityConfig{StatePath:shiftedPath})
			defer restored.Stop()
			run(newManager(restored),t.Name()+"-past-original-expiry","socket-retention-produced",false)
			if connections.Load()!=2 { t.Fatalf("actual connections=%d want=2",connections.Load()) }
		})
	}
}
