package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// codexTerminalOnlyCompletion is a completion that reports server-tool work no earlier frame
// announced, with a missing or wrong model. Without tool output it is the replay-safe control.
func codexTerminalOnlyCompletion(responseID, identity string, tool bool) string {
	model := ""
	if identity == "wrong" {
		model = `"model":"wrong-model",`
	}
	output := ""
	if tool {
		output = `{"id":"search_terminal_only","type":"web_search_call","status":"completed","action":{"type":"search","query":"fixture"}}`
	}
	return fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,%s"status":"completed","output":[%s]}}`, responseID, model, output)
}

// codexTerminalOnlyRun drives the real conductor and transport with a primary credential that
// sends frames and a secondary that succeeds, so a replay shows up as a second attempt.
func codexTerminalOnlyRun(t *testing.T, transport string, frames []string, responseFormat string) (result *cliproxyexecutor.StreamResult, err error, first, second int32, observed int) {
	t.Helper()
	var manager *cliproxyauth.Manager
	var attempts func() (int32, int32)
	var fixture *WSReplayFixture
	if strings.HasPrefix(transport, "sse") {
		var a, b interface{ Load() int32 }
		manager, a, b, _ = codexSSEReplayManager(t, frames, true)
		attempts = func() (int32, int32) { return a.Load(), b.Load() }
	} else {
		fixture = WSReplayNewFixture(t, true, frames)
		manager = fixture.manager
		attempts = func() (int32, int32) { return fixture.primaryRequests.Load(), fixture.secondaryRequests.Load() }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex"), Stream: true}
	if responseFormat != "" {
		opts.ResponseFormat = sdktranslator.FromString(responseFormat)
	}
	if fixture != nil {
		opts.WebSocketResponseObserver = func(_ context.Context, event cliproxyexecutor.WebSocketResponseEvent) {
			fixture.observerEvents = append(fixture.observerEvents, append([]byte(nil), event.Payload...))
		}
	}
	result, err = manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{
		Model: WSReplayModel, Payload: []byte(`{"model":"gpt-5.6-terra","input":[]}`),
	}, opts)
	first, second = attempts()
	if fixture != nil {
		observed = len(fixture.observerEvents)
	}
	return result, err, first, second, observed
}

func codexTerminalOnlyAssert(t *testing.T, tool bool, result *cliproxyexecutor.StreamResult, err error, first, second int32, observed int) {
	t.Helper()
	var payload string
	var streamErr error
	if result != nil {
		payload, streamErr = drainChunks(result)
	}
	if !tool {
		// Control: an output-free rejected completion is still replay-safe.
		if first != 1 || second != 1 {
			t.Errorf("safe control attempts = %d,%d, want 1,1", first, second)
		}
		if result == nil || err != nil || streamErr != nil || strings.Contains(payload, "search_terminal_only") {
			t.Errorf("safe control must complete on the second credential: result=%v err=%v streamErr=%v payload=%s", result, err, streamErr, payload)
		}
		return
	}
	if first != 1 || second != 0 {
		t.Errorf("completed server-tool work replayed: attempts = %d,%d, want 1,0", first, second)
	}
	if result != nil || payload != "" || streamErr != nil {
		t.Errorf("rejected completion leaked output: result=%v payload=%s streamErr=%v", result, payload, streamErr)
	}
	if observed != 0 {
		t.Errorf("rejected completion reached the websocket observer: %d events", observed)
	}
	if err == nil {
		t.Fatal("rejected completion lost its synchronous error")
	}
	var stop interface{ IsRequestStop() bool }
	if !errors.As(err, &stop) || !stop.IsRequestStop() {
		t.Errorf("rejected completion with tool work lost the request-stop marker: %T %v", err, err)
	}
	var mismatch *helps.CodexModelMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("original model mismatch lost: %T %v", err, err)
	}
}

// A completion is the first frame that shows upstream work and also fails identity. The work
// must close the replay latch before the identity rejection returns.
func TestCodexTerminalOnlyServerToolBootstrapDoesNotReplay(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, transport := range []string{"sse", "ws"} {
		for _, identity := range []string{"missing", "wrong"} {
			for _, tool := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s_identity/tool=%t", transport, identity, tool), func(t *testing.T) {
					responseID := "resp_sse_replay"
					if transport == "ws" {
						responseID = "resp_replay"
					}
					frames := []string{
						fmt.Sprintf(`{"type":"response.in_progress","response":{"id":%q}}`, responseID),
						codexTerminalOnlyCompletion(responseID, identity, tool),
					}
					result, err, first, second, observed := codexTerminalOnlyRun(t, transport, frames, "")
					codexTerminalOnlyAssert(t, tool, result, err, first, second, observed)
				})
			}
		}
	}
}

// After a verified identity, the live loop must also classify a wrong-model completion's work.
// The earlier frames translate to zero Gemini payloads, so the conductor can still retry.
func TestCodexTerminalOnlyServerToolLiveDoesNotReplay(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, transport := range []string{"sse", "ws"} {
		for _, tool := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/tool=%t", transport, tool), func(t *testing.T) {
				responseID, identity := "resp_sse_replay", codexSSEReplayIdentity
				if transport == "ws" {
					responseID, identity = "resp_replay", WSReplayIdentity
				}
				frames := []string{fmt.Sprintf(`{"type":"response.in_progress","response":{"id":%q}}`, responseID)}
				// Verify identity, then exhaust the frame budget so the completion reaches the live loop.
				for i := 0; i <= codexBootstrapMaxBufferedFrames; i++ {
					frames = append(frames, identity)
				}
				var state any
				for _, frame := range frames {
					if chunks := sdktranslator.TranslateStream(context.Background(), sdktranslator.FromString("codex"), sdktranslator.FromString("gemini"), WSReplayModel, nil, nil, []byte("data: "+frame), &state); len(chunks) != 0 {
						t.Fatalf("prefix must translate to zero chunks: frame=%s chunks=%q", frame, chunks)
					}
				}
				frames = append(frames, codexTerminalOnlyCompletion(responseID, "wrong", tool))
				result, err, first, second, _ := codexTerminalOnlyRun(t, transport, frames, "gemini")
				// Verified identity frames legitimately reach the observer, so only the SSE-shared checks apply.
				codexTerminalOnlyAssert(t, tool, result, err, first, second, 0)
			})
		}
	}
}
