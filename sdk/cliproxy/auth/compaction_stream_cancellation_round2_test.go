package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// This transport still uses a real HTTP server and the real Claude producer.
// It observes request cancellation and the producer's response-body Close.
type round2ProducerReceipt struct {
	ctx        context.Context
	bodyClosed <-chan struct{}
}

type round2ProducerTransport struct {
	requests chan round2ProducerReceipt
}

func (p *round2ProducerTransport) RoundTripperFor(*coreauth.Auth) http.RoundTripper { return p }

func (p *round2ProducerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	closed := make(chan struct{})
	p.requests <- round2ProducerReceipt{ctx: req.Context(), bodyClosed: closed}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		resp.Body = &round2ProducerBody{ReadCloser: resp.Body, closed: closed}
	}
	return resp, err
}

type round2ProducerBody struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (b *round2ProducerBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}

type round2ProducerHook struct {
	coreauth.NoopHook
	results chan coreauth.Result
}

func (h *round2ProducerHook) OnResult(_ context.Context, result coreauth.Result) { h.results <- result }

func TestCompactionStreamRound2RealClaudeProducerCancellation(t *testing.T) {
	for _, mode := range []string{"persistence-refusal", "budget-refusal", "downstream-cancel", "completion", "503-retry"} {
		t.Run(mode, func(t *testing.T) {
			const model = "claude-opus-5"
			statePath := filepath.Join(t.TempDir(), "affinity.state")
			selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &coreauth.FillFirstSelector{}, StatePath: statePath})
			defer selector.Stop()
			transport := &round2ProducerTransport{requests: make(chan round2ProducerReceipt, 8)}
			hook := &round2ProducerHook{results: make(chan coreauth.Result, 8)}
			var calls atomic.Int32
			release := make(chan struct{})
			upstreamCanceled := make(chan struct{}, 8)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if mode == "503-retry" && n == 1 {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = io.WriteString(w, `{"error":{"type":"overloaded_error","message":"retry ordinary request"}}`)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				writeEvent := func(name, data string) {
					_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
					w.(http.Flusher).Flush()
				}
				writeEvent("message_start", `{"type":"message_start","message":{"id":"msg_round2","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}`)
				if mode == "persistence-refusal" {
					// Selection has completed. Turn the snapshot target into a directory
					// so the next real synchronous publication fails on every platform.
					if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
						t.Error(err)
					}
					if err := os.Mkdir(statePath, 0o700); err != nil {
						t.Error(err)
					}
					writeEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"compaction","content":"round2-signed-summary"}}`)
				} else if mode == "budget-refusal" {
					for i := 0; i < 257; i++ {
						writeEvent("content_block_start", fmt.Sprintf(`{"type":"content_block_start","index":%d,"content_block":{"type":"compaction","content":"round2-signed-%d"}}`, i, i))
						writeEvent("content_block_stop", fmt.Sprintf(`{"type":"content_block_stop","index":%d}`, i))
					}
				} else if mode == "completion" || mode == "503-retry" {
					writeEvent("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":"ordinary complete"}}`)
					writeEvent("content_block_stop", `{"type":"content_block_stop","index":0}`)
					writeEvent("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`)
					writeEvent("message_stop", `{"type":"message_stop"}`)
					return
				}
				// Keep the HTTP body alive: no EOF, timeout, or caller cancellation
				// can masquerade as producer ownership on the refusal cases.
				select {
				case <-r.Context().Done():
					upstreamCanceled <- struct{}{}
				case <-release:
				}
			}))
			defer upstream.Close()
			defer close(release)
			manager := coreauth.NewManager(nil, selector, hook)
			manager.SetRetryConfig(0, 0, 0)
			manager.SetRoundTripperProvider(transport)
			manager.RegisterExecutor(runtimeexecutor.NewClaudeExecutor(&internalconfig.Config{}))
			for _, suffix := range []string{"A", "B"} {
				id := t.Name() + suffix
				if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "claude", Status: coreauth.StatusActive, Attributes: map[string]string{"api_key": "round2-fixture", "base_url": upstream.URL}}); err != nil {
					t.Fatal(err)
				}
				registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
				defer registry.GetGlobalRegistry().UnregisterClient(id)
			}
			parent := context.Background()
			var callerCancel context.CancelFunc
			if mode == "downstream-cancel" {
				parent, callerCancel = context.WithCancel(parent)
				defer callerCancel()
			}
			body := []byte(`{"model":"claude-opus-5","max_tokens":100,"messages":[{"role":"user","content":"hello"}],"stream":true}`)
			stream, err := manager.ExecuteStream(parent, []string{"claude"}, coreexecutor.Request{Model: model, Payload: body}, coreexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatClaude, OriginalRequest: body})
			if err != nil {
				t.Fatal(err)
			}
			requestReceipt := <-transport.requests
			if mode == "503-retry" {
				select {
				case <-requestReceipt.ctx.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("abandoned 503 attempt context was not canceled")
				}
				select {
				case <-requestReceipt.bodyClosed:
				case <-time.After(2 * time.Second):
					t.Fatal("abandoned 503 response body was not closed")
				}
				requestReceipt = <-transport.requests
			}
			if callerCancel != nil {
				callerCancel()
			}
			var terminal error
			// A hang bound, not a speed check: budget-refusal first makes 256
			// durable publications (file and directory fsync each, ~20 ms on Dev1).
			timer := time.NewTimer(20 * time.Second)
			defer timer.Stop()
		readStream:
			for {
				select {
				case chunk, ok := <-stream.Chunks:
					if !ok {
						break readStream
					}
					if chunk.Err != nil {
						terminal = chunk.Err
					}
					if mode == "persistence-refusal" && strings.Contains(string(chunk.Payload), "round2-signed-summary") {
						t.Fatal("refused signed output leaked")
					}
				case <-timer.C:
					t.Fatal("consumer did not terminate")
				}
			}
			refused := mode == "persistence-refusal" || mode == "budget-refusal"
			if refused && !coreauth.IsLocalCompactionAffinityStop(terminal) {
				t.Fatalf("terminal = %v, want typed local stop", terminal)
			}
			if mode == "budget-refusal" {
				var local *coreauth.Error
				if !errors.As(terminal, &local) || local.Code != "compaction_json_rejected" || !strings.Contains(local.Message, "compaction collection exceeds block or byte limit") {
					t.Fatalf("terminal = %v, want block-budget refusal rather than native framing refusal", terminal)
				}
			}
			if !refused && callerCancel == nil && terminal != nil {
				t.Fatalf("ordinary stream failed: %v", terminal)
			}
			if callerCancel == nil && parent.Err() != nil {
				t.Fatal("producer cancellation canceled SDK caller")
			}
			select {
			case <-requestReceipt.ctx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("producer request context still live after consumer terminal")
			}
			select {
			case <-requestReceipt.bodyClosed:
			case <-time.After(2 * time.Second):
				t.Fatal("real Claude producer did not close upstream response body")
			}
			if refused || callerCancel != nil {
				select {
				case <-upstreamCanceled:
				case <-time.After(2 * time.Second):
					t.Fatal("live upstream did not observe request cancellation")
				}
			}
			if refused || callerCancel != nil {
				select {
				case result := <-hook.results:
					t.Fatalf("local refusal/cancellation entered execution accounting: %+v", result)
				default:
				}
			}
			if mode == "completion" || mode == "503-retry" {
				var successes, failures int
			results:
				for {
					select {
					case result := <-hook.results:
						if result.Success {
							successes++
						} else {
							failures++
						}
					default:
						break results
					}
				}
				wantFailures := 0
				if mode == "503-retry" {
					wantFailures = 1
				}
				if successes != 1 || failures != wantFailures {
					t.Fatalf("accounting successes=%d failures=%d, want 1/%d", successes, failures, wantFailures)
				}
			}
			if mode == "503-retry" && calls.Load() != 2 {
				t.Fatalf("ordinary 503 retry calls = %d, want 2", calls.Load())
			}
		})
	}
}
