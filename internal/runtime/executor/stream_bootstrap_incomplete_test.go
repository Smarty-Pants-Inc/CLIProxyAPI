package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

// Recorded catch: PR #174 review/astra P1. Translation can produce zero chunks
// even after an explicit-off bootstrap releases the verified handshake.
func TestCodexBootstrapIncompleteWithoutTranslatedOutput(t *testing.T) {
	for _, transport := range []string{"http", "websocket"} {
		for _, buffering := range []bool{false, true} {
			for _, mode := range []string{"empty", "nonterminal", "complete"} {
				t.Run(transport+"/buffering="+map[bool]string{false: "off", true: "on"}[buffering]+"/"+mode, func(t *testing.T) {
					var events []string
					if mode != "empty" {
						events = append(events, codexCreatedEvent)
					}
					if mode == "complete" {
						events = append(events, codexCompletedEventBody)
					}
					cfg := codexBufferingConfig(true)
					if !buffering {
						cfg = codexBufferingExplicitlyOffConfig()
					}
					var server *httptest.Server
					var exec cliproxyauth.ProviderExecutor
					if transport == "http" {
						server = codexSSEServer(events...)
						exec = NewCodexExecutor(cfg)
					} else {
						server = codexWebsocketServer(t, events...)
						wsExec := NewCodexWebsocketsExecutor(cfg)
						defer wsExec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
						exec = wsExec
					}
					defer server.Close()
					req, opts := codexTestRequest()
					opts.ResponseFormat = sdktranslator.FormatOpenAI
					result, err := exec.ExecuteStream(t.Context(), codexTestAuth(server.URL), req, opts)
					var output string
					if result != nil {
						output, err = drainChunks(result)
					}
					if mode == "complete" {
						if err != nil || !strings.Contains(output, `"finish_reason":"stop"`) {
							t.Fatalf("terminal failed: output=%s err=%v", output, err)
						}
						return
					}
					var incomplete *helps.IncompleteStreamError
					if !errors.As(err, &incomplete) {
						t.Fatalf("missing incomplete error: output=%s err=%v", output, err)
					}
					detail := gjson.Get(err.Error(), "error")
					if detail.Get("code").String() != "upstream_stream_incomplete" || !detail.Get("retryable").Bool() || detail.Get("partial_bytes").Int() != 0 || detail.Get("partial_chunks").Int() != 0 {
						t.Fatalf("wrong incomplete diagnostics: %v", err)
					}
				})
			}
		}
	}
}

type bootstrapCancelEOFReader struct{ cancel context.CancelFunc }

func (r bootstrapCancelEOFReader) Read([]byte) (int, error) {
	r.cancel() // Make EOF and downstream cancellation ready in the same read.
	return 0, io.EOF
}

func TestBootstrapStreamCancellationWinsEOF(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, provider := range []string{"compat", "claude", "codex", "codex-ws"} {
		for _, prefix := range []string{"empty", "handshake"} {
			t.Run(provider+"/"+prefix, func(t *testing.T) {
				hook.Reset()
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				wire := ""
				if prefix == "handshake" {
					switch provider {
					case "compat":
						wire = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n"
					case "claude":
						wire = "data: {\"type\":\"ping\"}\n\n"
					default:
						wire = "data: " + codexCreatedEvent + "\n\n"
					}
				}
				ctx = context.WithValue(ctx, "cliproxy.roundtripper", issue6381RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(io.MultiReader(strings.NewReader(wire), bootstrapCancelEOFReader{cancel})), Request: req}, nil
				}))
				cfg := &config.Config{}
				var exec cliproxyauth.ProviderExecutor
				req, opts := codexTestRequest()
				auth := codexTestAuth("http://bootstrap.test")
				switch provider {
				case "compat":
					exec = NewOpenAICompatExecutor(provider, cfg)
					opts.SourceFormat = sdktranslator.FormatOpenAI
					req.Payload = []byte(`{"model":"test","messages":[{"role":"user","content":"proof"}]}`)
				case "claude":
					exec = NewClaudeExecutor(cfg)
					req.Model = "claude-opus-5-5"
					req.Payload = []byte(`{"model":"claude-opus-5-5","max_tokens":100,"messages":[{"role":"user","content":"proof"}]}`)
					opts.SourceFormat = sdktranslator.FormatClaude
				case "codex":
					exec = NewCodexExecutor(cfg)
				case "codex-ws":
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
						if err != nil {
							t.Error(err)
							return
						}
						defer func() {
							if errClose := conn.Close(); errClose != nil {
								t.Logf("close upstream websocket: %v", errClose)
							}
						}()
						if _, _, errRead := conn.ReadMessage(); errRead != nil {
							t.Error(errRead)
							return
						}
						if prefix == "handshake" {
							_ = conn.WriteMessage(websocket.TextMessage, []byte(codexCreatedEvent))
						}
						cancel()
					}))
					defer server.Close()
					auth = codexTestAuth(server.URL)
					wsExec := NewCodexWebsocketsExecutor(cfg)
					defer wsExec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
					exec = wsExec
				}
				result, err := exec.ExecuteStream(ctx, auth, req, opts)
				if result != nil {
					_, err = drainChunks(result)
				}
				if ctx.Err() == nil || (err != nil && !errors.Is(err, context.Canceled)) {
					t.Fatalf("cancellation lost: ctx=%v err=%v", ctx.Err(), err)
				}
				for _, entry := range hook.AllEntries() {
					if entry.Level == log.WarnLevel && entry.Message == "upstream stream incomplete" {
						t.Fatalf("client cancel logged as upstream cutoff: %v", entry.Data)
					}
				}
			})
		}
	}
}
