package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type codexDiagnosticReadFailure struct{ err error }

func (r codexDiagnosticReadFailure) Read([]byte) (int, error) { return 0, r.err }

// Recorded catch: the October 24 cutoff warning hid diagnostics in LogFormatter.
// Exercise both bootstrap EOF and EOF/read failure after downstream output.
func TestCodexIncompleteStreamWarnDiagnostics(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, buffered := range []bool{false, true} {
		for _, partial := range []bool{false, true} {
			for _, reset := range []bool{false, true} {
				name := map[bool]string{false: "unbuffered", true: "buffered"}[buffered] + "/" + map[bool]string{false: "bootstrap", true: "partial"}[partial] + "/" + map[bool]string{false: "EOF", true: "reset"}[reset]
				t.Run(name, func(t *testing.T) {
					hook.Reset()
					wire := "data: " + codexCreatedEvent + "\n\n"
					if partial {
						wire += "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"private-body-sentinel\"}\n\n"
					}
					var body io.Reader = strings.NewReader(wire)
					wantSignal := "EOF"
					if reset {
						body = io.MultiReader(body, codexDiagnosticReadFailure{errors.New("connection reset by peer; Authorization: Bearer secret-sentinel; private-body-sentinel")})
						wantSignal = "connection_reset"
					}
					ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", issue6381RoundTripperFunc(func(req *http.Request) (*http.Response, error) {
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/event-stream"}, "X-Private": {"header-sentinel"}}, Body: io.NopCloser(body), Request: req}, nil
					}))
					req, opts := codexTestRequest()
					result, err := NewCodexExecutor(codexBufferingConfig(buffered)).ExecuteStream(ctx, codexTestAuth("https://example.invalid"), req, opts)
					if result != nil {
						_, err = drainChunks(result)
					}
					var incomplete *helps.IncompleteStreamError
					if !errors.As(err, &incomplete) || incomplete.StatusCode() != http.StatusBadGateway {
						t.Fatalf("want incomplete 502, got %T %v", err, err)
					}
					if incomplete.IsRequestScoped() != partial {
						t.Fatalf("request scope changed: partial=%t scoped=%t", partial, incomplete.IsRequestScoped())
					}
					var warning *log.Entry
					for _, entry := range hook.AllEntries() {
						if entry.Level == log.WarnLevel && entry.Message == "upstream stream incomplete" {
							warning = entry
						}
					}
					if warning == nil {
						t.Fatal("missing incomplete-stream warning")
					}
					line, errFormat := (&logging.LogFormatter{}).Format(warning)
					if errFormat != nil {
						t.Fatal(errFormat)
					}
					for _, field := range []string{"provider=codex", "upstream_status=200", "upstream_error=\"" + wantSignal + "\"", "partial_bytes=", "partial_chunks=", "stream_elapsed_seconds="} {
						if !strings.Contains(string(line), field) {
							t.Errorf("missing %q in %s", field, line)
						}
					}
					for _, secret := range []string{"private-body-sentinel", "secret-sentinel", "header-sentinel", "Authorization", "X-Private"} {
						if strings.Contains(string(line), secret) {
							t.Errorf("sensitive upstream data %q in %s", secret, line)
						}
					}
					if elapsed, ok := warning.Data["stream_elapsed_seconds"].(float64); !ok || elapsed < 0 {
						t.Errorf("invalid elapsed seconds: %v", warning.Data)
					}
					if bytes, ok := warning.Data["partial_bytes"].(int64); !ok || (bytes > 0) != partial {
						t.Errorf("wrong byte count: %v", warning.Data)
					}
					if chunks, ok := warning.Data["partial_chunks"].(int64); !ok || (chunks > 0) != partial {
						t.Errorf("wrong chunk count: %v", warning.Data)
					}
					t.Log(strings.TrimSpace(string(line)))
				})
			}
		}
	}
}
