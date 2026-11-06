package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type quotaAcquisitionBody struct {
	io.Reader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *quotaAcquisitionBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return b.Reader.Read(p)
}

func (*quotaAcquisitionBody) Close() error { return nil }

// Keep: real executor transport/result boundaries and bootstrap failures are not
// covered by tests that only call the metadata holder directly. Gates establish
// ordering without timer granularity or wall-clock delays.
func TestHTTPQuotaAcquisitionPrecedesBodyCompletion(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		for _, stream := range []bool{false, true} {
			for _, outcome := range []string{"success", "http-error", "bootstrap-failure"} {
				if outcome == "bootstrap-failure" && (!stream || provider != "codex") {
					continue
				}
				t.Run(fmt.Sprintf("%s/stream=%t/%s", provider, stream, outcome), func(t *testing.T) {
					cfg := &config.Config{}
					var exec cliproxyauth.ProviderExecutor
					var req cliproxyexecutor.Request
					var opts cliproxyexecutor.Options
					var payload string
					var signal string
					if provider == "codex" {
						exec = NewCodexExecutor(cfg)
						req, opts = codexTestRequest()
						payload = "data: " + codexCreatedEvent + "\n\ndata: " + codexCompletedEventBody + "\n\n"
						signal = "X-Codex-Primary-Used-Percent"
					} else {
						exec = NewClaudeExecutor(cfg)
						req = cliproxyexecutor.Request{Model: "claude-opus-5-5", Payload: []byte(`{"model":"claude-opus-5-5","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`)}
						opts = cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("claude"), ResponseFormat: sdktranslator.FromString("claude")}
						payload = `{"id":"msg_fixture","type":"message","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`
						if stream {
							payload = "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\",\"type\":\"message\",\"model\":\"claude-opus-5-5\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\ndata: {\"type\":\"message_stop\"}\n\n"
						}
						signal = "Anthropic-Ratelimit-Unified-5h-Utilization"
					}
					opts.Stream = stream
					status := http.StatusOK
					if outcome == "http-error" {
						status, payload = http.StatusTooManyRequests, `{"error":{"message":"fixture quota"}}`
					} else if outcome == "bootstrap-failure" {
						payload = "data: " + codexCreatedEvent + "\n\ndata: " + codexOverloadEvent + "\n\n"
					}
					headers := http.Header{signal: {"0.2"}, "X-Fixture": {"unchanged"}, "Content-Type": {"application/json"}}
					if stream || provider == "codex" {
						headers.Set("Content-Type", "text/event-stream")
					}
					body := &quotaAcquisitionBody{Reader: strings.NewReader(payload), entered: make(chan struct{}), release: make(chan struct{})}
					var releaseOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(body.release) }) }
					defer release()
					ctx := logging.WithFreshResponseHeadersHolder(context.Background())
					ctx = context.WithValue(ctx, "cliproxy.roundtripper", roundTripperFunc(func(r *http.Request) (*http.Response, error) {
						if _, errRead := io.ReadAll(r.Body); errRead != nil {
							return nil, errRead
						}
						return &http.Response{StatusCode: status, Header: headers.Clone(), Body: body, Request: r}, nil
					}))
					credential := &cliproxyauth.Auth{ID: t.Name(), Provider: provider, Attributes: map[string]string{"api_key": "fixture-only"}}
					type result struct {
						headers http.Header
						err     error
					}
					done := make(chan result, 1)
					go func() {
						if stream {
							response, errExecute := exec.ExecuteStream(ctx, credential, req, opts)
							if errExecute != nil {
								done <- result{err: errExecute}
								return
							}
							_, errStream := drainChunks(response)
							done <- result{headers: response.Headers, err: errStream}
						} else {
							response, errExecute := exec.Execute(ctx, credential, req, opts)
							done <- result{headers: response.Headers, err: errExecute}
						}
					}()
					select {
					case <-body.entered:
					case early := <-done:
						t.Fatalf("executor returned before fixture body: %v", early.err)
					}
					gotHeaders, acquired := logging.GetResponseHeadersObservation(ctx)
					if acquired[signal].IsZero() || !reflect.DeepEqual(gotHeaders, headers) {
						t.Errorf("headers were not acquired before body read: %v %v", gotHeaders, acquired)
					}
					release()
					completed := <-done
					if (completed.err == nil) != (outcome == "success") {
						t.Fatalf("outcome=%s error=%v", outcome, completed.err)
					}
					_, after := logging.GetResponseHeadersObservation(ctx)
					if !reflect.DeepEqual(acquired, after) {
						t.Fatalf("completion restamped acquisition: before=%v after=%v", acquired, after)
					}
					if outcome == "success" && !reflect.DeepEqual(completed.headers, headers) {
						t.Fatalf("downstream headers changed: %v, want %v", completed.headers, headers)
					}
				})
			}
		}
	}
}
