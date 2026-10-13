package executor

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

const codexObserverCompletedEvent = `{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5.6-terra","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`

// codexObserverFrames is a full turn. Every frame after response.created must reach the
// WebSocketResponseObserver in wire order, whatever the bootstrap buffering mode.
var codexObserverFrames = []string{
	codexCreatedEvent,
	codexInProgressEvent,
	`{"type":"codex.rate_limits","rate_limits":{"primary":{"used_percent":75}}}`,
	codexOutputAddedEvent,
	codexOutputDeltaEvent,
	`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":" there"}`,
	codexObserverCompletedEvent,
}

// observeCodexWebsocketStream drives one streamed turn and returns the observed event types
// and payloads in the order the observer received them.
func observeCodexWebsocketStream(t *testing.T, cfg *config.Config) ([]string, []string) {
	t.Helper()
	server := codexWebsocketServer(t, codexObserverFrames...)
	defer server.Close()

	var mu sync.Mutex
	var types, payloads []string
	req, opts := codexWebsocketRequest()
	opts.WebSocketResponseObserver = func(_ context.Context, ev cliproxyexecutor.WebSocketResponseEvent) {
		mu.Lock()
		defer mu.Unlock()
		types = append(types, ev.EventType)
		payloads = append(payloads, string(ev.Payload))
	}

	result, err := NewCodexWebsocketsExecutor(cfg).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
	if err != nil {
		t.Fatalf("ExecuteStream error: %v", err)
	}
	combined, streamErr := drainChunks(result)
	if streamErr != nil {
		t.Fatalf("stream error: %v", streamErr)
	}
	if !strings.Contains(combined, `" there"`) {
		t.Fatalf("second delta missing from downstream stream: %s", combined)
	}
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), types...), append([]string(nil), payloads...)
}

// Regression (CLIProxyAPI#68 P2): the bootstrap loop observes frames only until it releases the
// stream (right after response.created when buffering is explicitly off, at the first output
// otherwise), and the streaming goroutine used to drop every later observer event. Each frame
// must be observed once, in wire order, in every mode.
func TestCodexWebsocketsExecutor_BootstrapBufferingDisabled_ObservesEveryEventInOrder(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"explicit_off", codexBufferingExplicitlyOffConfig()},
		{"default", &config.Config{}},
		{"explicit_on", codexBufferingConfig(true)},
	} {
		t.Run(tc.name, func(t *testing.T) { assertObservesEveryEventInOrder(t, tc.cfg) })
	}
}

func assertObservesEveryEventInOrder(t *testing.T, cfg *config.Config) {
	t.Helper()
	types, payloads := observeCodexWebsocketStream(t, cfg)
	want := []string{
		"response.created",
		"response.in_progress",
		"codex.rate_limits",
		"response.output_item.added",
		"response.output_text.delta",
		"response.output_text.delta",
		"response.completed",
	}
	if !reflect.DeepEqual(types, want) {
		t.Fatalf("observed event types = %v, want %v", types, want)
	}
	if !strings.Contains(payloads[2], `"used_percent":75`) {
		t.Fatalf("rate limit payload = %s", payloads[2])
	}
	if !strings.Contains(payloads[4], `"delta":"hi"`) || !strings.Contains(payloads[5], `"delta":" there"`) {
		t.Fatalf("delta payloads out of order: %s | %s", payloads[4], payloads[5])
	}
}
