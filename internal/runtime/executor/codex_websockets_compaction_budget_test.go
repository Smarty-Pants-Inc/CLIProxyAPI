package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// No fake executor or seeded signer evidence: every capsule comes from the
// actual websocket upstream and is observed through public Manager.ExecuteStream.
func TestCodexDuplexCompactionLogicalResponseBudget(t *testing.T) {
	runCodexDuplexCompactionBudget(t, false)
}

func TestCodexDuplexCompactionRejectsSingle257Response(t *testing.T) {
	runCodexDuplexCompactionBudget(t, true)
}

func runCodexDuplexCompactionBudget(t *testing.T, overlimit bool) {
	responses := 130
	if overlimit {
		responses = 1
	}
	var connections, creates atomic.Int32
	serverDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(serverDone)
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		connections.Add(1)
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		for i := 0; i < responses; i++ {
			_, request, errRead := conn.ReadMessage()
			if errRead != nil {
				return
			}
			if gjson.GetBytes(request, "type").String() != "response.create" {
				t.Errorf("upstream create %d: %s", i, request)
				return
			}
			creates.Add(1)
			events := []string{fmt.Sprintf(`{"type":"response.created","response":{"id":"r%d","model":"socket-budget-model","output":[]}}`, i)}
			items := 1
			if overlimit {
				items = 257
			}
			blocks := make([]string, 0, items)
			for j := 0; j < items; j++ {
				content := fmt.Sprintf("socket-budget-%d", i)
				if overlimit {
					content = fmt.Sprintf("socket-budget-%d-item-%d", i, j)
				}
				block := fmt.Sprintf(`{"type":"compaction","encrypted_content":%q}`, content)
				blocks = append(blocks, block)
				events = append(events, fmt.Sprintf(`{"type":"response.output_item.done","response_id":"r%d","output_index":%d,"item":%s}`, i, j, block))
			}
			events = append(events, fmt.Sprintf(`{"type":"response.completed","response":{"id":"r%d","model":"socket-budget-model","output":[%s]}}`, i, strings.Join(blocks, ",")))
			for _, event := range events {
				if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(event)); errWrite != nil {
					return
				}
			}
		}
		_, _, _ = conn.ReadMessage()
	}))
	defer upstream.Close()
	cfg := &config.Config{}
	cfg.Codex.ResponseSteering = true
	cfg.CodexResponseSteering = true
	origin := auth.NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := auth.NewManager(nil, origin, nil)
	manager.SetConfig(cfg)
	manager.RegisterExecutor(NewCodexAutoExecutor(cfg))
	id, model := "socket-budget-A", "socket-budget-model"
	_, err := manager.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "test-key", "base_url": upstream.URL, "websockets": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	defer registry.GetGlobalRegistry().UnregisterClient(id)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	input := make(chan core.WebsocketInput, 1)
	ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
	payload := []byte(`{"model":"socket-budget-model","input":[]}`)
	stream, err := manager.ExecuteStream(ctx, []string{"codex"}, core.Request{Model: model, Payload: payload}, core.Options{SourceFormat: translator.FormatCodex, OriginalRequest: payload, Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()}})
	if err != nil {
		t.Fatal(err)
	}
	completed, deliveredItems := 0, 0
	var streamErr error
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			streamErr = chunk.Err
			cancel()
			continue
		}
		if gjson.GetBytes(chunk.Payload, "type").String() == "response.output_item.done" {
			deliveredItems++
		}
		if gjson.GetBytes(chunk.Payload, "type").String() != "response.completed" {
			continue
		}
		completed++
		// Public replay admission proves actual output registration, not a stub.
		opts, errPrepare := manager.PrepareCompactionRequest(model, core.Options{OriginalRequest: []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":"socket-budget-%d"}]}`, completed-1))}, ctx)
		if errPrepare != nil {
			t.Fatalf("unregistered signed delivery: %v", errPrepare)
		}
		validate, ok := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
		if !ok || validate == nil {
			t.Fatal("real output validator absent")
		}
		if errValidate := validate(id, opts.OriginalRequest); errValidate != nil {
			t.Fatal(errValidate)
		}
		if completed == responses {
			cancel()
			break
		}
		input <- core.WebsocketInput{Payload: []byte(`{"type":"response.create","input":[]}`)}
	}
	cancel()
	for range stream.Chunks {
	}
	select {
	case <-serverDone:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream socket did not close")
	}
	if overlimit {
		if !auth.IsLocalCompactionAffinityStop(streamErr) || completed != 0 || deliveredItems != 256 || connections.Load() != 1 || creates.Load() != 1 {
			t.Fatalf("single 257-block response: err=%v completed=%d delivered=%d connections=%d creates=%d", streamErr, completed, deliveredItems, connections.Load(), creates.Load())
		}
		current, ok := manager.GetByID(id)
		if !ok || current.Unavailable || !current.NextRetryAfter.IsZero() {
			t.Fatal("local output refusal changed credential availability")
		}
		return
	}
	if streamErr != nil || completed != responses || connections.Load() != 1 || creates.Load() != int32(responses) {
		t.Fatalf("err=%v completed=%d connections=%d actual upstream creates=%d", streamErr, completed, connections.Load(), creates.Load())
	}
}
