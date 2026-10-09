package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	translator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// Use the real public preparation method on both the reviewed two-argument
// parent and the context-aware fix. This adapter changes only the call shape,
// never the captured validator or its result, so the same test can expose the
// parent's actual upstream receipt rather than merely failing to compile.
func prepareCodexDuplexAmbiguousRequest(t *testing.T, manager *auth.Manager, model string, opts core.Options, ctx context.Context) core.Options {
	t.Helper()
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	opts.Metadata["compaction_request_context"] = ctx
	var prepared core.Options
	var err error
	switch prepare := any(manager.PrepareCompactionRequest).(type) {
	case func(string, core.Options, ...context.Context) (core.Options, error):
		prepared, err = prepare(model, opts, ctx)
	case func(string, core.Options, context.Context) (core.Options, error):
		prepared, err = prepare(model, opts, ctx)
	case func(string, core.Options) (core.Options, error):
		prepared, err = prepare(model, opts)
	default:
		t.Fatal("unsupported public compaction preparation signature")
	}
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

type codexDuplexAmbiguousUsage struct {
	baseURL string
	barrier string
	done    chan struct{}
	failed  atomic.Int32
	success atomic.Int32
}

func (p *codexDuplexAmbiguousUsage) HandleUsage(_ context.Context, record usage.Record) {
	if p.done != nil && record.Provider == "duplex-test-barrier" && record.TraceID == p.barrier {
		close(p.done)
		return
	}
	if p.baseURL == "" || record.BaseURL != p.baseURL {
		return
	}
	if record.Failed {
		p.failed.Add(1)
	} else {
		p.success.Add(1)
	}
}

func TestCodexDuplexAmbiguousJSONRealManagerBeforeWrite(t *testing.T) {
	const model = "gpt-6-astra"
	knownA := `{"type":"compaction","encrypted_content":"known-a"}`
	cases := []struct {
		name    string
		payload string
		code    string
		status  int
	}{
		{"ordinary", " { \"type\":\"response.steer\", \"previous_response_id\":\"first\", \"input\":[{\"type\":\"function_call_output\",\"call_id\":\"call-1\",\"output\":\"ok\"}], \"unknown_field\":{\"keep\":\"raw\"} }\n", "", 0},
		{"known-a", `{"type":"response.steer","previous_response_id":"first","input":[` + knownA + `],"unknown_field":{"keep":"raw"}}`, "", 0},
		// Every entry is known on A: the finite block limit must count blocks,
		// not just distinct digests, and cannot silently truncate constraints.
		{"257-blocks", `{"type":"response.steer","previous_response_id":"first","input":[` + strings.Repeat(knownA+",", 256) + knownA + `]}`, "compaction_json_rejected", http.StatusBadRequest},
		{"mixed-signers", `{"type":"response.steer","previous_response_id":"first","input":[` + knownA + `,{"type":"compaction","encrypted_content":"known-b"}]}`, "compaction_affinity_conflict", http.StatusConflict},
		{"unknown-signer", `{"type":"response.steer","previous_response_id":"first","input":[{"type":"compaction","encrypted_content":"unknown"}]}`, "compaction_affinity_missing", http.StatusConflict},
	}
	for _, last := range []string{"known-b", "unknown"} {
		block := fmt.Sprintf(`{"type":"compaction","encrypted_content":%q}`, last)
		for _, duplicate := range []struct{ name, fields string }{
			{"root-input", `"input":[],"input":[` + block + `]`},
			{"block-type", `"input":[{"type":"message","type":"compaction","encrypted_content":"` + last + `"}]`},
			{"block-encrypted-content", `"input":[{"type":"compaction","encrypted_content":"known-a","encrypted_content":"` + last + `"}]`},
			{"native-content", `"messages":[{"role":"user","content":[],"content":[` + block + `]}]`},
			{"native-block-content", `"messages":[{"content":[{"type":"compaction","encrypted_content":"known-a","content":"ordinary","content":"` + last + `"}]}]`},
			{"escaped-root-input", `"input":[],"\u0069nput":[` + block + `]`},
			{"escaped-block-type", `"input":[{"type":"message","\u0074ype":"compaction","encrypted_content":"` + last + `"}]`},
			{"escaped-encrypted-content", `"input":[{"type":"compaction","encrypted_content":"known-a","\u0065ncrypted_content":"` + last + `"}]`},
			{"nested-object", `"input":[],"unknown_field":{"member":"ordinary","member":"` + last + `"}`},
		} {
			cases = append(cases, struct {
				name    string
				payload string
				code    string
				status  int
			}{duplicate.name + "/" + last, `{"type":"response.steer","previous_response_id":"first",` + duplicate.fields + `}`, "compaction_json_rejected", http.StatusBadRequest})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed := tc.code == ""
			submitted := []byte(tc.payload)
			original := bytes.Clone(submitted)
			var connections, initialWrites, followupWrites atomic.Int32
			serverDone := make(chan struct{}, 4)
			serverErrors := make(chan error, 8)
			receipts := make(chan []byte, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer func() { serverDone <- struct{}{} }()
				connections.Add(1)
				if r.Header.Get("Authorization") != "Bearer duplex-dummy-account-a" {
					serverErrors <- fmt.Errorf("socket used unexpected account")
					return
				}
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					serverErrors <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
				_ = conn.SetWriteDeadline(time.Now().Add(8 * time.Second))
				_, initial, err := conn.ReadMessage()
				if err != nil {
					serverErrors <- err
					return
				}
				initialWrites.Add(1)
				if gjson.GetBytes(initial, "type").String() != "response.create" || gjson.GetBytes(initial, "model").String() != model || len(gjson.GetBytes(initial, "input").Array()) != 0 {
					serverErrors <- fmt.Errorf("bootstrap was not ordinary create on requested model: %s", initial)
					return
				}
				write := func(payload string) bool {
					if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(payload)); errWrite != nil {
						serverErrors <- errWrite
						return false
					}
					return true
				}
				if !write(`{"type":"response.created","response":{"id":"first","model":"gpt-6-astra","output":[]}}`) ||
					!write(`{"type":"response.completed","response":{"id":"first","model":"gpt-6-astra","output":[]}}`) {
					return
				}
				// A refused client closes its own socket. Waiting for this receipt
				// barrier proves absence of writes without a timing-based sleep.
				for {
					_, payload, errRead := conn.ReadMessage()
					if errRead != nil {
						var timeout net.Error
						if errors.As(errRead, &timeout) && timeout.Timeout() {
							serverErrors <- fmt.Errorf("receipt barrier ended by deadline, not client socket closure: %w", errRead)
						}
						return
					}
					followupWrites.Add(1)
					receipts <- payload
					// Acknowledge even forbidden receipts, so the vulnerable parent
					// fails on the real write, not a hung stream or an upstream error.
					if !write(`{"type":"response.steer.accepted","steer":{"id":"s1","previous_response_id":"first"}}`) ||
						!write(`{"type":"response.created","response":{"id":"second","previous_response_id":"first","model":"gpt-6-astra","output":[]}}`) ||
						!write(`{"type":"response.completed","response":{"id":"second","model":"gpt-6-astra","output":[]}}`) {
						return
					}
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			input := make(chan core.WebsocketInput, 1)
			ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), input)
			candidate := &auth.Auth{ID: "A", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{
				"api_key": "duplex-dummy-account-a", "base_url": server.URL, "websockets": "true",
			}}
			ctx = core.WithWebsocketAuthCheck(ctx, func(id string) bool {
				return id == candidate.ID && candidate.Status == auth.StatusActive && !candidate.Disabled
			})
			origin := auth.NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager := auth.NewManager(nil, origin, nil)
			for _, signer := range []struct{ id, block string }{{"A", "known-a"}, {"B", "known-b"}} {
				output := []byte(fmt.Sprintf(`{"output":[{"type":"compaction","encrypted_content":%q}]}`, signer.block))
				if err := origin.RecordCompactionOutput(signer.id, core.Options{}, output); err != nil {
					t.Fatal(err)
				}
			}
			initial := []byte(`{"model":"gpt-6-astra","input":[]}`)
			opts := prepareCodexDuplexAmbiguousRequest(t, manager, model, core.Options{
				SourceFormat: translator.FromString("codex"), OriginalRequest: initial,
				Metadata: map[string]any{core.ExecutionSessionMetadataKey: t.Name()},
			}, ctx)
			if validate, ok := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error); !ok || validate == nil {
				t.Fatal("direct Manager preparation did not install real validator without auth selection")
			}
			capture := &codexDuplexAmbiguousUsage{baseURL: server.URL, barrier: t.Name(), done: make(chan struct{})}
			usage.RegisterNamedPlugin(t.Name(), capture)
			t.Cleanup(func() { usage.RegisterNamedPlugin(t.Name(), &codexDuplexAmbiguousUsage{}) })
			exec := NewCodexWebsocketsExecutor(&config.Config{Codex: config.CodexConfig{ResponseSteering: true}})
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			// Execute directly: no handler, provider registry, selector.Pick, or
			// provider budget can substitute for the captured real callback.
			result, err := exec.ExecuteStream(ctx, candidate, core.Request{Model: model, Payload: initial}, opts)
			if err != nil {
				t.Fatal(err)
			}
			var streamErr error
			var completedFirst, completedSecond bool
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					streamErr = chunk.Err
					continue
				}
				if gjson.GetBytes(chunk.Payload, "type").String() != "response.completed" {
					continue
				}
				switch gjson.GetBytes(chunk.Payload, "response.id").String() {
				case "first":
					if completedFirst {
						t.Error("duplicate bootstrap completion")
						cancel()
						continue
					}
					completedFirst = true
					input <- core.WebsocketInput{Payload: submitted}
				case "second":
					completedSecond = true
					cancel()
				}
			}
			select {
			case <-serverDone:
			case <-time.After(3 * time.Second):
				t.Fatal("socket did not close at receipt barrier")
			}
			for len(serverErrors) > 0 {
				t.Error(<-serverErrors)
			}
			if !completedFirst || connections.Load() != 1 || initialWrites.Load() != 1 {
				t.Fatalf("bootstrap/connection mismatch: complete=%v connections=%d initial=%d", completedFirst, connections.Load(), initialWrites.Load())
			}
			if !bytes.Equal(submitted, original) {
				t.Fatal("validator normalized raw downstream bytes")
			}
			// The usage dispatcher is FIFO. This marker, enqueued after the
			// stream closes, drains all actual usage before checking failures.
			usage.PublishRecord(context.Background(), usage.Record{Provider: "duplex-test-barrier", TraceID: capture.barrier})
			select {
			case <-capture.done:
			case <-time.After(time.Second):
				t.Fatal("usage receipt barrier did not drain")
			}
			if capture.failed.Load() != 0 || capture.success.Load() == 0 {
				t.Fatalf("local refusal published upstream failure usage: failures=%d successes=%d", capture.failed.Load(), capture.success.Load())
			}
			// Credential receiver/cooldown policy is tested by auth's owner;
			// this layer must preserve its local cause, scope, and stop marker.
			if candidate.Unavailable || !candidate.NextRetryAfter.IsZero() || candidate.LastError != nil || len(candidate.ModelStates) != 0 {
				t.Fatal("standalone executor mutated credential cooldown state")
			}
			if allowed {
				if streamErr != nil || !completedSecond || followupWrites.Load() != 1 || len(receipts) != 1 {
					t.Fatalf("valid steer: err=%v completed=%v writes=%d receipts=%d", streamErr, completedSecond, followupWrites.Load(), len(receipts))
				}
				if receipt := <-receipts; !bytes.Equal(receipt, original) {
					t.Fatalf("valid raw steer changed on actual wire: %q", receipt)
				}
				return
			}
			if followupWrites.Load() != 0 || len(receipts) != 0 || completedSecond {
				t.Fatalf("rejected steer reached upstream: writes=%d receipts=%d successor=%v err=%v", followupWrites.Load(), len(receipts), completedSecond, streamErr)
			}
			var local *codexDuplexAffinityError
			var cause *auth.Error
			wrapped := fmt.Errorf("runtime boundary: %w", streamErr)
			if !errors.As(streamErr, &local) || !errors.As(streamErr, &cause) || cause.Code != tc.code || local.StatusCode() != tc.status || !local.IsRequestScoped() || !errors.Is(streamErr, cause) || !auth.IsLocalCompactionAffinityStop(wrapped) {
				t.Fatalf("rejection lost typed cause/status/request scope/local marker: %v", streamErr)
			}
		})
	}
}

func TestCodexDuplexAmbiguousJSONNegativeManagerOrigin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manager := auth.NewManager(nil, nil, nil)
	opts := prepareCodexDuplexAmbiguousRequest(t, manager, "gpt-6-astra", core.Options{}, ctx)
	if _, exists := opts.Metadata[core.CompactionAffinityValidatorMetadataKey]; exists {
		t.Fatal("Manager without local origin installed a validator")
	}
	origin := auth.NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager.SetSelector(origin)
	opts = prepareCodexDuplexAmbiguousRequest(t, manager, "gpt-6-astra", opts, ctx)
	if _, exists := opts.Metadata[core.CompactionAffinityValidatorMetadataKey]; exists {
		t.Fatal("captured nil origin acquired authority after selector reload")
	}
}
