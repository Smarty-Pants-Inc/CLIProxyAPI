package auth

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	codexresponses "github.com/router-for-me/CLIProxyAPI/v7/internal/translator/codex/openai/responses"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Use the actual Scanner + Responses translator contract, without importing
// the runtime executor into auth (which would introduce an import cycle).
type compactionScannerExecutor struct {
	*compactionAffinityExecutor
	wire        string
	release     <-chan struct{}
	afterSigned <-chan struct{}
}

func (e *compactionScannerExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if errAttempt := e.attempt(ctx, auth, opts); errAttempt != nil {
		return nil, errAttempt
	}
	chunks := make(chan cliproxyexecutor.StreamChunk)
	go func() {
		defer close(chunks)
		scanner := bufio.NewScanner(strings.NewReader(e.wire))
		var param any
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			// Keep the stream live after its first ordinary data event. The
			// consumer must receive that event before it releases signed output.
			if bytes.Equal(line, []byte("event: response.output_item.done")) {
				select {
				case <-e.release:
				case <-ctx.Done():
					return
				}
			}
			for _, payload := range codexresponses.ConvertCodexResponseToOpenAIResponses(ctx, req.Model, opts.OriginalRequest, req.Payload, line, &param) {
				select {
				case chunks <- cliproxyexecutor.StreamChunk{Payload: payload}:
				case <-ctx.Done():
					return
				}
			}
			if e.afterSigned != nil && bytes.Contains(line, []byte(producedCompaction)) {
				select {
				case <-e.afterSigned:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}

func TestManagerCompactionCodexScannerContractLiveAndRestart(t *testing.T) {
	model := "scanner-compaction-model"
	firstID, secondID := t.Name()+"-A", t.Name()+"-B"
	statePath := filepath.Join(t.TempDir(), "affinity.state")
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &compactionAffinityFallback{preferredID: firstID}, StatePath: statePath,
	})
	defer selector.Stop()
	base := &compactionAffinityExecutor{provider: "codex", firstID: firstID}
	manager := newCompactionAffinityManager(t, selector, base, model, secondID)
	release := make(chan struct{})
	wire := ": keepalive\nevent: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"model\":\"" + model + "\"}}\n\n" +
		"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":" + producedCompaction + "}\n\n: keepalive\ndata: [DONE]\n\n"
	manager.RegisterExecutor(&compactionScannerExecutor{compactionAffinityExecutor: base, wire: wire, release: release})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, opts := compactionAffinityRequest(model, "none", false, false)
	stream, errStream := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
	if errStream != nil {
		t.Fatal(errStream)
	}
	// A finite watchdog prevents a broken observer from hanging the suite;
	// channel release, not elapsed time, establishes the ordering assertion.
	watchdog := time.NewTimer(3 * time.Second)
	defer watchdog.Stop()
	wantChunks := []string{
		": keepalive", "event: response.created",
		`data: {"type":"response.created","response":{"model":"` + model + `"}}`,
		"event: response.output_item.done",
		`data: {"type":"response.output_item.done","item":` + producedCompaction + `}`,
		": keepalive", "data: [DONE]",
	}
	index := 0
	for {
		select {
		case <-watchdog.C:
			t.Fatalf("live Scanner stream stalled at chunk %d before barrier release", index)
		case chunk, ok := <-stream.Chunks:
			if !ok {
				if index != len(wantChunks) {
					t.Fatalf("received %d chunks, want %d", index, len(wantChunks))
				}
				goto drained
			}
			if chunk.Err != nil || index >= len(wantChunks) || string(chunk.Payload) != wantChunks[index] {
				t.Fatalf("Scanner chunk %d changed: %q, %v", index, chunk.Payload, chunk.Err)
			}
			if index == 2 {
				close(release)
			}
			if bytes.Contains(chunk.Payload, []byte(producedCompaction)) {
				for _, key := range compactionOutputKeys(chunk.Payload[6:]) {
					if signer, known := selector.cache.Get(key); !known || signer != firstID || !selector.cache.IsProtected(key) {
						t.Fatal("signed Scanner output delivered before registration")
					}
				}
			}
			index++
		}
	}

drained:
	selector.Stop()
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
	})
	defer restarted.Stop()
	base.attempts = nil
	base.failure = errors.New("signed account unavailable")
	manager = newCompactionAffinityManager(t, restarted, base, model, secondID)
	req, opts = compactionAffinityRequest(model, "none", true, false)
	if _, errReplay := manager.ExecuteStream(ctx, []string{"codex"}, req, opts); errReplay == nil {
		t.Fatal("first replay unexpectedly succeeded")
	}
	assertCompactionAffinityOnlyA(t, base, true)
	if len(base.attempts) != 1 {
		t.Fatalf("first replay attempts = %v, want only producing A", base.attempts)
	}
}

func TestManagerCompactionCodexScannerMultilineBeforeCompletion(t *testing.T) {
	model := "scanner-multiline-model"
	firstID, secondID := t.Name()+"-A", t.Name()+"-B"
	path := filepath.Join(t.TempDir(), "affinity.state")
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &compactionAffinityFallback{preferredID: firstID}, StatePath: path})
	defer selector.Stop()
	base := &compactionAffinityExecutor{provider: "codex", firstID: firstID}
	manager := newCompactionAffinityManager(t, selector, base, model, secondID)
	release := make(chan struct{})
	close(release)
	afterSigned := make(chan struct{})
	wire := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"model\":\"" + model + "\"}}\n\n" +
		"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\ndata: \"item\":" + producedCompaction + "}\n\n" +
		"data: {\"type\":\"response.completed\"}\n\n"
	manager.RegisterExecutor(&compactionScannerExecutor{compactionAffinityExecutor: base, wire: wire, release: release, afterSigned: afterSigned})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, opts := compactionAffinityRequest(model, "none", false, false)
	stream, err := manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"event: response.created", `data: {"type":"response.created","response":{"model":"` + model + `"}}`, "event: response.output_item.done", `data: {"type":"response.output_item.done",`, `data: "item":` + producedCompaction + `}`}
	for i, expected := range want {
		select {
		case <-ctx.Done():
			t.Fatalf("multiline delivery stalled at %d", i)
		case chunk := <-stream.Chunks:
			if chunk.Err != nil || string(chunk.Payload) != expected {
				t.Fatalf("chunk %d = %q, %v", i, chunk.Payload, chunk.Err)
			}
			if i >= 3 {
				for _, key := range compactionOutputKeys([]byte(`{"type":"response.output_item.done","item":` + producedCompaction + `}`)) {
					if id, ok := selector.cache.Get(key); !ok || id != firstID || !selector.cache.IsProtected(key) {
						t.Fatal("multiline bytes released before protected A registration")
					}
				}
			}
		}
	}
	// No completion/error may repair registration: upstream is still blocked.
	selector.Stop()
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: path})
	defer restarted.Stop()
	base.attempts = nil
	base.failure = errors.New("signed account unavailable")
	replay := newCompactionAffinityManager(t, restarted, base, model, secondID)
	req, opts = compactionAffinityRequest(model, "none", true, false)
	if _, err = replay.ExecuteStream(ctx, []string{"codex"}, req, opts); err == nil {
		t.Fatal("first replay unexpectedly succeeded")
	}
	assertCompactionAffinityOnlyA(t, base, true)
	if len(base.attempts) != 1 {
		t.Fatalf("replay attempts = %v", base.attempts)
	}
	cancel()
}

func TestCompactionOutputStreamBytewiseRawFraming(t *testing.T) {
	event := `{"type":"response.output_item.done","item":` + producedCompaction + `}`
	for _, wire := range []string{
		event,
		"data: " + event,
		": keepalive\nevent: response.output_item.done\ndata: " + event + "\n\n",
		": keepalive\r\nid: response-id\r\nretry: 1000\r\nevent: response.output_item.done\r\ndata: " + event + "\r\n\r\n",
	} {
		registered := false
		observer := &compactionOutputStream{record: func(payload []byte) error {
			registered = registered || len(compactionOutputKeys(payload)) > 0
			return nil
		}}
		var delivered []byte
		for i := range wire {
			ready, errSave := observer.push([]byte{wire[i]})
			if errSave != nil {
				t.Fatal(errSave)
			}
			delivered = append(delivered, ready...)
			if bytes.Contains(delivered, []byte(event)) && !registered {
				t.Fatal("bytewise signed event delivered before registration")
			}
		}
		tail, errSave := observer.finish()
		delivered = append(delivered, tail...)
		if errSave != nil || !registered || string(delivered) != wire {
			t.Fatalf("bytewise wire changed: registered=%v, wire=%q, err=%v", registered, delivered, errSave)
		}
	}
}

func TestCompactionOutputStreamRejectsUnexaminedTail(t *testing.T) {
	observer := &compactionOutputStream{record: func([]byte) error { return nil }}
	if ready, errSave := observer.push([]byte(`data: {"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"partial`)); errSave != nil || len(ready) != 0 {
		t.Fatalf("partial event leaked: %q, %v", ready, errSave)
	}
	if ready, errSave := observer.finish(); errSave == nil || len(ready) != 0 {
		t.Fatalf("unexamined EOF tail leaked: %q, %v", ready, errSave)
	}
}

func TestCompactionOutputStoreExplicitNoLocalStore(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{
		compactionAffinityStoreMetadataKey: (*SessionAffinitySelector)(nil),
	}}
	if manager.compactionOutputStore(opts) != nil {
		t.Fatal("captured no-local-store decision fell back to current selector")
	}
	if manager.compactionOutputStore(cliproxyexecutor.Options{}) != selector {
		t.Fatal("absent origin did not retain legacy fallback")
	}
}
