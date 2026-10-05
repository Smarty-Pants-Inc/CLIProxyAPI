package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const nativeClaudeBlock = `{"type":"compaction","content":"native-signed-summary"}`

func nativeClaudeEvent(event string) []byte { return []byte("data: " + event + "\n\n") }

func nativeClaudeRequest(model, block string, primary bool) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	content := `[{"type":"text","text":"continue"}]`
	if block != "" {
		content = "[" + block + "]"
	}
	body := []byte(`{"model":"` + model + `","messages":[{"role":"assistant","content":` + content + `},{"role":"user","content":"continue"}]}`)
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, OriginalRequest: body, Metadata: map[string]any{cliproxyexecutor.CallerScopeMetadataKey: "native-caller"}}
	if primary {
		opts.Headers = make(http.Header)
		opts.Headers.Set("Session-Id", "native-conversation")
	}
	return cliproxyexecutor.Request{Model: model, Payload: body}, opts
}

func TestManagerNativeClaudeProductionFirstReplay(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		for _, restart := range []bool{false, true} {
			name := path + "/fresh"
			if restart {
				name = path + "/restart-before-first-replay"
			}
			t.Run(name, func(t *testing.T) {
				const model = "native-compaction-model"
				firstID, secondID := t.Name()+"-A", t.Name()+"-B"
				statePath := filepath.Join(t.TempDir(), "affinity.state")
				selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath})
				defer selector.Stop()
				executor := &compactionAffinityExecutor{provider: "claude", firstID: firstID, bootstrapChunk: path == "stream-bootstrap", output: []byte(`{"content":[` + nativeClaudeBlock + `]}`), streamOutput: [][]byte{
					nativeClaudeEvent(`{"type":"content_block_start","index":0,"content_block":{"type":"compaction","content":""}}`),
					nativeClaudeEvent(`{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"native-signed-"}}`),
					nativeClaudeEvent(`{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"summary"}}`),
					nativeClaudeEvent(`{"type":"content_block_stop","index":0}`),
				}}
				manager := newCompactionAffinityManager(t, selector, executor, model, secondID)
				manager.SetPluginScheduler(&fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, AuthID: firstID}})
				req, opts := nativeClaudeRequest(model, "", true)
				if err := runCompactionAffinityRequest(t, manager, executor, path, req, opts); err != nil {
					t.Fatal(err)
				}
				if len(executor.attempts) != 1 || executor.attempts[0].authID != firstID {
					t.Fatalf("production = %v", executor.attempts)
				}
				primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
				if primaryID == "" {
					t.Fatal("native fixture did not supply an explicit session")
				}
				primary := "mixed::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + model
				if !selector.cache.IsProtected(primary) {
					t.Fatal("native production did not protect primary")
				}
				if restart {
					selector.Stop()
					selector = NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath})
					defer selector.Stop()
				}
				manager = newCompactionAffinityManager(t, selector, executor, model, secondID)
				executor.output, executor.streamOutput, executor.attempts = nil, nil, nil
				executor.failure = compactTestStatusError{code: http.StatusServiceUnavailable, msg: "native A forced 503"}
				// Fresh options, reordered/whitespace JSON, no explicit session ID.
				req, opts = nativeClaudeRequest(model, `{ "content" : "native-signed-summary", "type" : "compaction" }`, false)
				err := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
				var status cliproxyexecutor.StatusError
				if !errors.As(err, &status) || status.StatusCode() != http.StatusServiceUnavailable {
					t.Fatalf("first replay = %v, want A 503", err)
				}
				assertCompactionAffinityOnlyA(t, executor, true)
				if len(executor.attempts) != 1 {
					t.Fatalf("first replay executions = %v, want A once, B zero", executor.attempts)
				}
			})
		}
	}
}

func TestNativeClaudeStreamRegistersCompleteStartAndAssembledDeltas(t *testing.T) {
	for _, skeleton := range []bool{false, true} {
		startBlock := nativeClaudeBlock
		if skeleton {
			startBlock = `{"type":"compaction","content":""}`
		}
		start := nativeClaudeEvent(`{"type":"content_block_start","index":3,"content_block":` + startBlock + `}`)
		delta := nativeClaudeEvent(`{"type":"content_block_delta","index":3,"delta":{"type":"compaction_delta","content":"native-signed-summary"}}`)
		stop := nativeClaudeEvent(`{"type":"content_block_stop","index":3}`)
		for split := 1; split < len(start); split++ {
			registered := false
			observer := &compactionOutputStream{native: true, ctx: context.Background(), record: func(payload []byte) error {
				if len(compactionOutputKeys(payload)) > 0 {
					registered = true
				}
				return nil
			}}
			var delivered []byte
			for _, part := range [][]byte{start[:split], start[split:]} {
				ready, err := observer.push(part)
				if err != nil {
					t.Fatal(err)
				}
				delivered = append(delivered, ready...)
			}
			if skeleton {
				if bytes.Contains(delivered, []byte(`"content_block"`)) || registered {
					t.Fatalf("skeleton leaked at split %d: %s", split, delivered)
				}
				ready, err := observer.push(delta)
				if err != nil || len(ready) != 0 || registered {
					t.Fatalf("delta leaked before stop: %s, %v", ready, err)
				}
			} else if !registered || !bytes.Equal(delivered, start) {
				t.Fatalf("complete start not registered before release: %s", delivered)
			}
			ready, err := observer.push(stop)
			if err != nil || !registered {
				t.Fatalf("completion failed: %v", err)
			}
			delivered = append(delivered, ready...)
			want := string(start) + string(stop)
			if skeleton {
				want = string(start) + string(delta) + string(stop)
			}
			if string(delivered) != want {
				t.Fatalf("native wire changed: %q want %q", delivered, want)
			}
		}
	}
}

func TestNativeClaudeStreamFailureNeverLeaksSignedContent(t *testing.T) {
	for _, incomplete := range []bool{false, true} {
		selector := NewSessionAffinitySelector(nil)
		manager := NewManager(nil, selector, nil)
		_, opts := nativeClaudeRequest("native-save-model", "", false)
		chunks := make(chan cliproxyexecutor.StreamChunk, 3)
		chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(`{"type":"content_block_start","index":0,"content_block":{"type":"compaction","content":""}}`)}
		chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(`{"type":"content_block_delta","index":0,"delta":{"type":"compaction_delta","content":"native-signed-summary"}}`)}
		if !incomplete {
			selector.cache.mu.Lock()
			selector.cache.persistenceErr = errors.New("disk failure")
			selector.cache.mu.Unlock()
			chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(`{"type":"content_block_stop","index":0}`)}
		}
		close(chunks)
		hook := &recordingHook{}
		manager.hook = hook
		stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "claude", "native-save-model", "native-save-model", nil, nil, chunks, OAuthModelAliasResult{}, false, opts)
		var wire []byte
		var terminal error
		for chunk := range stream.Chunks {
			wire = append(wire, chunk.Payload...)
			if chunk.Err != nil {
				terminal = chunk.Err
			}
		}
		selector.Stop()
		if strings.Contains(string(wire), "native-signed-summary") || terminal == nil || !IsLocalCompactionAffinityStop(terminal) {
			t.Fatalf("signed failure leaked or lost local stop: %q, %v", wire, terminal)
		}
		if hook.lastResult.Load() != nil {
			t.Fatal("local registration error entered credential accounting")
		}
	}
}

func TestRepeatedSignedOutputRefreshesExpiredEvidenceBeforeAck(t *testing.T) {
	for _, native := range []bool{false, true} {
		selector := NewSessionAffinitySelector(nil)
		manager := NewManager(nil, selector, nil)
		format := sdktranslator.FormatOpenAIResponse
		block := producedCompaction
		first := nativeClaudeEvent(`{"type":"response.output_item.added","item":` + block + `}`)
		last := nativeClaudeEvent(`{"type":"response.output_item.done","item":` + block + `}`)
		if native {
			format, block = sdktranslator.FormatClaude, nativeClaudeBlock
			first = nativeClaudeEvent(`{"type":"content_block_start","index":0,"content_block":` + block + `}`)
			last = nativeClaudeEvent(`{"type":"content_block_stop","index":0}`)
		}
		key := compactionBlockKeys(gjson.Parse("[" + block + "]"))[0]
		chunks := make(chan cliproxyexecutor.StreamChunk)
		stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "claude", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, cliproxyexecutor.Options{SourceFormat: format})
		chunks <- cliproxyexecutor.StreamChunk{Payload: first}
		firstChunk := <-stream.Chunks
		if firstChunk.Err != nil {
			t.Fatal(firstChunk.Err)
		}
		selector.cache.mu.Lock()
		for primary, entry := range selector.cache.groups {
			entry.expiresAt = time.Now().Add(-time.Hour)
			selector.cache.groups[primary] = entry
			for _, alias := range entry.aliases {
				selector.cache.entries[alias] = entry
			}
		}
		selector.cache.mu.Unlock()
		chunks <- cliproxyexecutor.StreamChunk{Payload: last}
		lastChunk := <-stream.Chunks
		if lastChunk.Err != nil {
			t.Fatal(lastChunk.Err)
		}
		if signer, known := selector.cache.Get(key); !known || signer != "A" || !selector.cache.IsProtected(key) {
			t.Errorf("repeated final ack delivered after evidence expired: native=%v signer=%s known=%v", native, signer, known)
		}
		close(chunks)
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				t.Error(chunk.Err)
			}
		}
		selector.Stop()
	}
}

func TestNativeClaudeStableOutputIdentityAndBoundedCollection(t *testing.T) {
	for _, pair := range [][2]string{
		{nativeClaudeBlock, `{ "content":"native-signed-summary", "type":"compaction" }`},
		{`{"type":"compaction","content":{"b":2,"a":1}}`, `{ "content": {"a":1, "b":2}, "type":"compaction" }`},
	} {
		output := compactionOutputKeys([]byte(`{"content":[` + pair[0] + `]}`))
		input := compactionBlockKeys(gjson.Parse("[" + pair[1] + "]"))
		if len(output) != 1 || len(input) != 1 || output[0] != input[0] {
			t.Fatalf("native identity differs: output=%v input=%v", output, input)
		}
	}
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	var blocks []string
	for i := 0; i < 257; i++ {
		blocks = append(blocks, fmt.Sprintf(`{"type":"compaction","content":"native-%d"}`, i))
	}
	payload := []byte(`{"content":[` + strings.Join(blocks, ",") + `]}`)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, payload); err == nil {
		t.Fatal("257 native output blocks silently truncated or accepted")
	}
	first := compactionBlockKeys(gjson.Parse("[" + blocks[0] + "]"))[0]
	if _, known := selector.cache.Get(first); known {
		t.Fatal("rejected output mutated signer state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	opts := cliproxyexecutor.Options{Metadata: map[string]any{compactionRequestContextMetadataKey: ctx}}
	if err := selector.RecordCompactionOutput("A", opts, []byte(`{"content":[`+nativeClaudeBlock+`]}`)); err == nil {
		t.Fatal("canceled output registered signer")
	}
}

func TestObservedOutputStreamHasWholeResponseBound(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	chunks := make(chan cliproxyexecutor.StreamChunk, 257)
	for i := 0; i < 257; i++ {
		chunks <- cliproxyexecutor.StreamChunk{Payload: nativeClaudeEvent(fmt.Sprintf(`{"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"whole-stream-%d"}}`, i))}
	}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
	var terminal error
	var delivered []byte
	for chunk := range stream.Chunks {
		delivered = append(delivered, chunk.Payload...)
		if chunk.Err != nil {
			terminal = chunk.Err
		}
	}
	if terminal == nil || !IsLocalCompactionAffinityStop(terminal) {
		t.Fatalf("257-block stream did not stop locally: %v", terminal)
	}
	if bytes.Contains(delivered, []byte(`"whole-stream-256"`)) {
		t.Fatal("over-budget block delivered without registration")
	}
}

func TestNativeClaudeOrdinaryAndEmptyBlocksPassPromptly(t *testing.T) {
	observer := &compactionOutputStream{native: true, ctx: context.Background(), record: func([]byte) error { return nil }}
	for _, wire := range []string{": ping\n", "event: content_block_start\n", string(nativeClaudeEvent(`{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)), string(nativeClaudeEvent(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`)), string(nativeClaudeEvent(`{"type":"content_block_stop","index":0}`)), string(nativeClaudeEvent(`{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"tool1","name":"read","input":{}}}`)), string(nativeClaudeEvent(`{"type":"content_block_stop","index":1}`))} {
		ready, err := observer.push([]byte(wire))
		if err != nil || string(ready) != wire {
			t.Fatalf("ordinary native event held/changed: %q, %v", ready, err)
		}
	}
	start := nativeClaudeEvent(`{"type":"content_block_start","index":2,"content_block":{"type":"compaction","content":""}}`)
	stop := nativeClaudeEvent(`{"type":"content_block_stop","index":2}`)
	if ready, err := observer.push(start); err != nil || len(ready) != 0 {
		t.Fatalf("empty skeleton: %q, %v", ready, err)
	}
	if ready, err := observer.push(stop); err != nil || string(ready) != string(start)+string(stop) {
		t.Fatalf("empty block changed: %q, %v", ready, err)
	}
}
