package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// The first regression deliberately uses only APIs present on the reviewed base.
// The stream observer receives decoded JSON after its existing SSE framing.
func TestCompactionDuplexLogicalResponseBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		responses  int
		blockBytes int
	}{
		{"occurrences", 130, 16},
		{"aggregate_bytes", 10, 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager := NewManager(nil, origin, nil)
			ctx := core.WithWebsocketInput(core.WithDownstreamWebsocket(context.Background()), make(chan core.WebsocketInput))
			chunks := make(chan core.StreamChunk, tc.responses*3)
			var want []byte
			for i := 0; i < tc.responses; i++ {
				block := fmt.Sprintf(`{"type":"compaction","encrypted_content":%q}`, fmt.Sprintf("budget-%d-", i)+strings.Repeat("x", tc.blockBytes))
				for _, payload := range []string{
					fmt.Sprintf(`{"type":"response.created","response":{"id":"r%d","output":[]}}`, i),
					fmt.Sprintf(`{"type":"response.output_item.done","response_id":"r%d","item":%s}`, i, block),
					fmt.Sprintf(`{"type":"response.completed","response":{"id":"r%d","output":[%s]}}`, i, block),
				} {
					wire := []byte("data: " + payload + "\n\n")
					want = append(want, wire...)
					chunks <- core.StreamChunk{Payload: wire}
				}
			}
			close(chunks)
			stream := manager.wrapStreamResult(ctx, &Auth{ID: "A"}, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, core.Options{SourceFormat: translator.FormatOpenAIResponse})
			var got []byte
			for chunk := range stream.Chunks {
				if chunk.Err != nil {
					t.Fatalf("individually valid response rejected after %d bytes: %v", len(got), chunk.Err)
				}
				for _, key := range compactionOutputKeys(compactionSSEData(chunk.Payload)) {
					if id, ok := origin.cache.Get(key); !ok || id != "A" || !origin.cache.IsProtected(key) {
						t.Fatal("signed acknowledgement released before evidence registration")
					}
				}
				got = append(got, chunk.Payload...)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("wire changed: got %d bytes, want %d", len(got), len(want))
			}
			for i := 0; i < tc.responses; i++ {
				input := []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":%q}]}`, fmt.Sprintf("budget-%d-", i)+strings.Repeat("x", tc.blockBytes)))
				keys := compactionAffinityKeys(core.Options{OriginalRequest: input})
				if len(keys) != 1 {
					t.Fatal("missing replay key")
				}
				if id, ok := origin.cache.Get(keys[0]); !ok || id != "A" || !origin.cache.IsProtected(keys[0]) {
					t.Fatalf("response %d released without signer evidence", i)
				}
			}
		})
	}
}

// Refusal probes retain ordinary stream bounds and prevent response-ID events
// from manufacturing a fresh quota inside one genuine logical response.
func TestCompactionResponseBudgetRefusesCounterexamples(t *testing.T) {
	block := `{"type":"compaction","encrypted_content":"one-response"}`
	for _, name := range []string{"single_257", "single_bytes", "ordinary_stream", "same_id_created", "same_id_terminal_composite", "mismatched_terminal", "missing_terminal_id", "new_id_before_terminal", "mismatched_output"} {
		t.Run(name, func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager := NewManager(nil, origin, nil)
			ctx := context.Background()
			if name != "ordinary_stream" {
				ctx = core.WithWebsocketInput(core.WithDownstreamWebsocket(ctx), make(chan core.WebsocketInput))
			}
			payloads := []string{`{"type":"response.created","response":{"id":"r1","output":[]}}`}
			if name == "mismatched_terminal" || name == "missing_terminal_id" || name == "new_id_before_terminal" || name == "mismatched_output" {
				payloads = append(payloads, `{"type":"response.output_item.done","response_id":"r1","item":`+block+`}`)
				if name == "mismatched_terminal" {
					payloads = append(payloads, `{"type":"response.failed","response":{"id":"unrelated","output":[]}}`)
				}
				if name == "mismatched_output" {
					payloads = append(payloads, `{"type":"response.output_item.done","response_id":"r2","item":`+block+`}`)
				}
				if name == "missing_terminal_id" {
					payloads = append(payloads, `{"type":"response.completed","response":{"output":[]}}`)
				}
				payloads = append(payloads, `{"type":"response.created","response":{"id":"r2","output":[]}}`)
			} else {
				count := 257
				item := block
				if name == "single_bytes" {
					count = 17
					item = fmt.Sprintf(`{"type":"compaction","encrypted_content":%q}`, strings.Repeat("x", 1<<20))
				}
				for i := 0; i < count; i++ {
					if name == "ordinary_stream" {
						payloads = append(payloads, fmt.Sprintf(`{"type":"response.created","response":{"id":"r%d","output":[]}}`, i))
					}
					payloads = append(payloads, `{"type":"response.output_item.done","response_id":"r1","item":`+item+`}`)
					switch name {
					case "same_id_created":
						payloads = append(payloads, `{"type":"response.created","response":{"id":"r1","output":[]}}`)
					case "same_id_terminal_composite":
						payloads = append(payloads, `{"type":"response.completed","response":{"id":"r1","output":[`+item+`]}}`, `{"type":"response.created","response":{"id":"r1","output":[`+item+`]}}`)
					case "ordinary_stream":
						payloads = append(payloads, fmt.Sprintf(`{"type":"response.completed","response":{"id":"r%d","output":[]}}`, i))
					}
				}
			}
			chunks := make(chan core.StreamChunk, len(payloads))
			for _, payload := range payloads {
				chunks <- core.StreamChunk{Payload: []byte(payload)}
			}
			close(chunks)
			candidate := &Auth{ID: "A"}
			stream := manager.wrapStreamResult(ctx, candidate, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, core.Options{SourceFormat: translator.FormatOpenAIResponse})
			var terminal error
			for chunk := range stream.Chunks {
				if chunk.Err != nil {
					terminal = chunk.Err
				}
			}
			var local *Error
			if !IsLocalCompactionAffinityStop(terminal) || !errors.As(terminal, &local) || local.Code != "compaction_json_rejected" {
				t.Fatalf("counterexample accepted or lost typed local stop: %v", terminal)
			}
			if candidate.Unavailable || !candidate.NextRetryAfter.IsZero() {
				t.Fatal("local budget stop changed credential availability")
			}
		})
	}
}

// This new-helper-only section follows the preserved BASE-compatible snapshot.
func TestCompactionResponseRecorderBoundariesAndAuthority(t *testing.T) {
	for _, terminal := range []string{"response.completed", "response.failed", "response.cancelled", "response.incomplete"} {
		t.Run(terminal, func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager := NewManager(nil, origin, nil)
			ctx := core.WithWebsocketInput(context.Background(), make(chan core.WebsocketInput))
			record := manager.newCompactionOutputRecorder(ctx, "A", core.Options{SourceFormat: translator.FormatOpenAIResponse})
			if record == nil {
				t.Fatal("manual SDK fallback origin absent")
			}
			for i := 0; i < 130; i++ {
				block := fmt.Sprintf(`{"type":"compaction","encrypted_content":"boundary-%d"}`, i)
				for _, payload := range []string{
					fmt.Sprintf(`{"type":"response.created","response":{"id":"r%d","output":[]}}`, i),
					fmt.Sprintf(`{"type":"response.output_item.done","response_id":"r%d","item":%s}`, i, block),
					fmt.Sprintf(`{"type":%q,"response":{"id":"r%d","output":[%s]}}`, terminal, i, block),
				} {
					if err := record([]byte(payload)); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	for _, captured := range []bool{false, true} {
		t.Run(fmt.Sprintf("origin_negative_%v", captured), func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			other := NewSessionAffinitySelector(nil)
			defer other.Stop()
			manager := NewManager(nil, origin, nil)
			opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, Metadata: map[string]any{}}
			if captured {
				opts.Metadata[compactionAffinityStoreMetadataKey] = (*SessionAffinitySelector)(nil)
			}
			record := manager.newCompactionOutputRecorder(context.Background(), "A", opts)
			manager.SetSelector(other)
			if captured {
				if record != nil {
					t.Fatal("negative origin acquired observer")
				}
				return
			}
			if err := record([]byte(`{"output":[{"type":"compaction","encrypted_content":"origin-captured"}]}`)); err != nil {
				t.Fatal(err)
			}
			keys := compactionOutputKeys([]byte(`{"output":[{"type":"compaction","encrypted_content":"origin-captured"}]}`))
			if id, ok := origin.cache.Get(keys[0]); !ok || id != "A" {
				t.Fatal("lost origin store")
			}
			if _, ok := other.cache.Get(keys[0]); ok {
				t.Fatal("output registered in replacement store")
			}
		})
	}
}

func TestCompactionResponseRecorderRepeatedAcknowledgementRefresh(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	record := manager.newCompactionOutputRecorder(context.Background(), "A", core.Options{SourceFormat: translator.FormatOpenAIResponse})
	done := []byte(`{"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"refresh-block"}}`)
	if err := record(done); err != nil {
		t.Fatal(err)
	}
	key := compactionOutputKeys(done)[0]
	// Age real observed evidence without sleeps; the completed acknowledgement
	// must restore the full retention window before release.
	origin.cache.mu.Lock()
	entry := origin.cache.entries[key]
	entry.expiresAt = time.Now().Add(time.Minute)
	origin.cache.entries[key] = entry
	for primary, group := range origin.cache.groups {
		if group.authID == "A" {
			group.expiresAt = entry.expiresAt
			origin.cache.groups[primary] = group
		}
	}
	origin.cache.mu.Unlock()
	if err := record([]byte(`{"type":"response.completed","response":{"output":[{"type":"compaction","encrypted_content":"refresh-block"}]}}`)); err != nil {
		t.Fatal(err)
	}
	origin.cache.mu.RLock()
	refreshed := origin.cache.entries[key].expiresAt
	origin.cache.mu.RUnlock()
	if !refreshed.After(entry.expiresAt) {
		t.Fatal("deduplication suppressed acknowledgement refresh")
	}
	// A repeated acknowledgement cannot bypass newly failed persistence either.
	origin.cache.mu.Lock()
	origin.cache.persistenceErr = errors.New("test persistence failure")
	origin.cache.mu.Unlock()
	if err := record(done); err == nil {
		t.Fatal("repeated acknowledgement skipped failed evidence check")
	}
}

func TestCompactionResponseRecorderChildCancellation(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	ctx, cancel := context.WithCancel(context.Background())
	opts := core.Options{SourceFormat: translator.FormatOpenAIResponse, Metadata: map[string]any{compactionRequestContextMetadataKey: context.Background()}}
	record := manager.newCompactionOutputRecorder(ctx, "A", opts)
	cancel()
	payload := []byte(`{"output":[{"type":"compaction","encrypted_content":"cancel-child"}]}`)
	if err := record(payload); !errors.Is(err, context.Canceled) {
		t.Fatalf("child cancellation did not stop recording: %v", err)
	}
	key := compactionOutputKeys(payload)[0]
	if _, ok := origin.cache.Get(key); ok {
		t.Fatal("canceled child registered signer evidence")
	}
}
