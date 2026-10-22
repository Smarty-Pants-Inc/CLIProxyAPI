package helps

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

// Trust boundary: only bounded, sanitized error diagnostics may cross from an
// untrusted upstream into client responses and ordinary application logs.
func TestStreamProgressUpstreamError(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, test := range []struct {
		name, payload, code, kind string
		retryable                 bool
	}{
		{"server code only", `{"type":"error","code":"server_error","message":"busy"}`, "server_error", "server_error", true},
		{"overload", `{"error":{"type":"overloaded_error","code":"overloaded","message":"busy"}}`, "overloaded", "overloaded_error", true},
		{"rate limit", `{"error":{"type":"rate_limit_error","code":429,"message":"slow down"}}`, "429", "rate_limit_error", true},
		{"5xx", `{"error":{"type":"api_error","code":"fixture","status":503,"message":"busy"}}`, "fixture", "api_error", true},
		{"invalid", `{"response":{"error":{"type":"invalid_request_error","code":"cyber_policy","message":"not allowed"}}}`, "cyber_policy", "invalid_request_error", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := StreamProgress{Bytes: 123, Chunks: 2}
			cause := errors.New("private original failure")
			err := p.UpstreamError(context.Background(), "codex", "gpt-test", "fixture label", 502, []byte(test.payload), cause)
			node := gjson.Get(err.Error(), "error")
			if node.Get("code").String() != test.code || node.Get("type").String() != test.kind || node.Get("retryable").Bool() != test.retryable {
				t.Fatalf("bad diagnostic: %v", err)
			}
			if !errors.Is(err, cause) {
				t.Fatal("lost internal classification cause")
			}
			if got := err.(*UpstreamStreamError).StatusCode(); got != http.StatusBadGateway {
				t.Fatalf("changed executor status to %d", got)
			}
		})
	}
	hook.Reset()
	p := StreamProgress{Bytes: 123, Chunks: 2}
	data := []byte(`{"type":"response.failed","sequence_number":9,"response":{"error":{"code":"server_error","type":"server_error","message":"busy sk-test-supersecret123456789 token=token-private owner@example.com ` + strings.Repeat("z", 1000) + `","api_key":"do-not-copy","extra":{"token":"nested-private"}}}}`)
	err := p.UpstreamError(context.Background(), "provider owner@example.com", "model sk-test-supersecret123456789", "label token=label-private", 200, data, nil)
	for _, secret := range []string{"sk-test-supersecret123456789", "token-private", "owner@example.com", "do-not-copy", "nested-private", "label-private"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("client leaked %s: %v", secret, err)
		}
		for _, entry := range hook.AllEntries() {
			s, _ := entry.String()
			if strings.Contains(s, secret) {
				t.Errorf("log leaked %s: %s", secret, s)
			}
		}
	}
	if n := len([]rune(gjson.Get(err.Error(), "error.message").String())); n > 303 {
		t.Fatalf("unbounded message: %d", n)
	}
	if gjson.Get(err.Error(), "error.extra").Exists() || gjson.Get(err.Error(), "error.api_key").Exists() {
		t.Fatalf("copied non-allowlisted fields: %v", err)
	}
	if gjson.Get(err.Error(), "sequence_number").Int() != 9 {
		t.Fatalf("lost upstream sequence number: %v", err)
	}
	if len(hook.AllEntries()) != 1 {
		t.Fatalf("want one warn: %v", hook.AllEntries())
	}
	hook.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := p.UpstreamError(ctx, "codex", "model", "label", 200, data, nil); got != context.Canceled {
		t.Fatalf("cancel became upstream error: %v", got)
	}
	if len(hook.AllEntries()) != 0 {
		t.Fatal("client cancellation logged as an upstream error")
	}
}

func TestStreamSSEData(t *testing.T) {
	var state StreamSSEData
	readyCount := 0
	for _, line := range []string{"event: error", `data: {"error":`, `data: {"code":"server_error","message":"busy"}}`} {
		data, ready := state.Observe([]byte(line))
		if ready {
			readyCount++
		}
		if ready && (!IsStreamErrorFrame(data, state.Event) || gjson.GetBytes(data, "error.code").String() != "server_error") {
			t.Fatalf("bad reconstructed error: %s", data)
		}
	}
	if readyCount != 1 {
		t.Fatalf("reconstructed %d events, want one", readyCount)
	}
	if state.Event != "error" {
		t.Fatal("lost SSE event name")
	}
	state.Observe(nil)
	data, ready := state.Observe([]byte(`data: {"type":"message_stop"}`))
	if !ready || IsStreamErrorFrame(data, state.Event) {
		t.Fatalf("error state leaked across frame boundary: %s", data)
	}
}
