package auth_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// BASE-compatible RED on the real Codex HTTP Scanner -> registered Responses
// translator -> public Manager. Setup and bootstrap are outside the allocation
// receipt; the barrier is released only after authoritative ordinary output.
func TestCompactionOutputRound3RealCodexHTTPAllocationBound(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprint(signed), func(t *testing.T) {
			round3RealCodexHTTP(t, 4096, signed, false, nil)
		})
	}
}

func round3RealCodexHTTP(t *testing.T, count int, signed, cancelTail bool, decorate func(context.Context) context.Context) {
	t.Helper()
	const model = "gpt-5.4"
	const block = `{"type":"compaction","encrypted_content":"round3-http-signed"}`
	units := []string{`data: {"type":"response.output_item.done","padding":[`}
	for i := 0; i < count; i++ {
		units = append(units, "data: 0,")
	}
	last := `data: 0],"item":{"type":"message","content":[]}}`
	if signed {
		last = `data: 0],"item":` + block + `}`
	}
	units = append(units, last)
	if len(strings.Join(units, "\n")) >= 1<<20 {
		t.Fatal("fixture must remain below 1 MiB")
	}
	release := make(chan struct{})
	partial := make(chan struct{})
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(closed)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"round3\",\"model\":%q}}\n\n", model)
		fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ready\"}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		for i, unit := range units {
			if cancelTail && i == len(units)-1 {
				w.(http.Flusher).Flush()
				close(partial)
				<-r.Context().Done()
				return
			}
			if _, err := fmt.Fprintln(w, unit); err != nil {
				return
			}
		}
		fmt.Fprint(w, "\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"round3\",\"model\":\"gpt-5.4\",\"status\":\"completed\",\"output\":[]}}\n\n")
		w.(http.Flusher).Flush()
	}))
	defer server.Close()
	selector := cliproxyauth.NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := cliproxyauth.NewManager(nil, selector, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(runtimeexecutor.NewCodexExecutor(&config.Config{}))
	id := t.Name() + "-A"
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	defer registry.GetGlobalRegistry().UnregisterClient(id)
	if _, err := manager.Register(context.Background(), &cliproxyauth.Auth{
		ID: id, Provider: "codex", Status: cliproxyauth.StatusActive,
		Attributes: map[string]string{"base_url": server.URL, "api_key": "round3-local"},
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if decorate != nil {
		ctx = decorate(ctx)
	}
	body := []byte(`{"model":"gpt-5.4","input":"hello","stream":true}`)
	opts := cliproxyexecutor.Options{Stream: true, SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: body}
	stream, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{Model: model, Payload: body}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for {
		select {
		case <-ctx.Done():
			t.Fatal("authoritative bootstrap did not reach consumer")
		case chunk, ok := <-stream.Chunks:
			if !ok || chunk.Err != nil {
				t.Fatalf("bootstrap closed/error: %v", chunk.Err)
			}
			if bytes.Contains(chunk.Payload, []byte(`"delta":"ready"`)) {
				goto bootstrapDone
			}
		}
	}
bootstrapDone:
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	close(release)
	if cancelTail {
		select {
		case <-partial:
		case <-ctx.Done():
			t.Fatal("upstream did not reach incomplete-tail barrier")
		}
		cancel()
	}
	index := 0
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			if cancelTail {
				continue
			}
			t.Fatal(chunk.Err)
		}
		if index < len(units) && string(chunk.Payload) == units[index] {
			if signed && index == 0 {
				// Before even the first retained unit is visible, attribution to
				// another producing account must already conflict with actual A.
				if err := manager.RecordCompactionOutput("B", cliproxyexecutor.Options{}, []byte(`{"output":[`+block+`]}`)); err == nil {
					t.Fatal("signed multiline bytes delivered before A registration")
				}
			}
			index++
		} else if index < len(units) && len(chunk.Payload) != 0 {
			t.Fatalf("original Scanner unit %d changed: %q", index, chunk.Payload)
		}
	}
	runtime.ReadMemStats(&after)
	if cancelTail {
		if index != 0 {
			t.Fatalf("canceled partial event released %d units", index)
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("cancellation did not close the real HTTP producer")
		}
		return
	}
	if index != len(units) {
		t.Fatalf("delivered %d original units, want %d", index, len(units))
	}
	// Upstream translator and final validation are included. A generous linear
	// ceiling permits their ordinary allocations, but not O(N^2) prefix copies.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(count)*4096+16<<20 {
		t.Fatalf("real HTTP path allocated %d bytes for %d short units", allocated, count)
	}
}

// GREEN-only private lexical checkpoint: the actual HTTP executor performs the
// Scanner and registered translation, and Manager creates the instrumented
// observer. Count completed-data inspection too, not merely stored input units.
func TestCompactionOutputRound3RealCodexHTTPHundredThousandUnitsLinear(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprint(signed), func(t *testing.T) {
			work := 0
			round3RealCodexHTTP(t, 100000, signed, false, func(ctx context.Context) context.Context {
				return cliproxyauth.Round3FramingWorkContext(ctx, func(n int) { work += n })
			})
			if work == 0 || work > 3*(100000*9+4096) {
				t.Fatalf("actual Scanner -> Responses -> Manager visits=%d; want nonzero linear work", work)
			}
		})
	}
}

func TestCompactionOutputRound3RealCodexHTTPIncompleteCancellation(t *testing.T) {
	work := 0
	round3RealCodexHTTP(t, 100000, true, true, func(ctx context.Context) context.Context {
		return cliproxyauth.Round3FramingWorkContext(ctx, func(n int) { work += n })
	})
	if work > 3*(100000*9+4096) {
		t.Fatalf("canceled real HTTP event performed superlinear work: %d", work)
	}
}
