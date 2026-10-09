package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	log "github.com/sirupsen/logrus"
)

func TestVertexAccessTokenFailureLogsAreSafeAcrossRequestPaths(t *testing.T) {
	// A generated, local-only key passes Vertex normalization. An unsupported
	// credential type then fails Google credential parsing before TokenSource.Token.
	// There is no token URI, token endpoint, or real credential in this test.
	var serviceAccount map[string]any
	if err := json.Unmarshal(testVertexServiceAccountJSON(t, ""), &serviceAccount); err != nil {
		t.Fatal(err)
	}
	delete(serviceAccount, "token_uri")
	delete(serviceAccount, "client_email")

	logger := log.StandardLogger()
	oldOutput, oldFormatter, oldLevel := logger.Out, logger.Formatter, logger.GetLevel()
	t.Cleanup(func() {
		logger.SetOutput(oldOutput)
		logger.SetFormatter(oldFormatter)
		logger.SetLevel(oldLevel)
	})
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableColors: true})
	logger.SetLevel(log.ErrorLevel)

	for _, diagnostic := range []struct {
		name, credentialType string
	}{
		{"token-and-error-sequence", "connection refused; access_token=synthetic-access-secret refresh_token=synthetic-refresh-secret Bearer synthetic-bearer-secret\nUNLABELED-SECRET\x1b[31m injected-error-sequence"},
		{"benign-signal", "connection refused"},
	} {
		for _, path := range []struct {
			name         string
			stream       bool
			count        bool
			interactions bool
		}{
			{name: "execute"},
			{name: "stream", stream: true},
			{name: "count", count: true},
			{name: "interactions", interactions: true},
			{name: "interactions-stream", stream: true, interactions: true},
		} {
			t.Run(diagnostic.name+"/"+path.name, func(t *testing.T) {
				output.Reset()
				serviceAccount["type"] = diagnostic.credentialType
				auth := &cliproxyauth.Auth{
					ID: "synthetic-redaction", Provider: "vertex",
					Metadata: map[string]any{
						"project_id": "synthetic-redaction", "location": "global",
						"service_account": serviceAccount,
						"interactions":    path.interactions,
					},
				}
				attempts := 0
				ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(roundTripperFunc(func(*http.Request) (*http.Response, error) {
					attempts++
					return nil, errors.New("network forbidden in redaction test")
				})))
				// Establish that the synthetic diagnostic really reaches errTok,
				// rather than accidentally passing on a different early failure.
				_, _, raw, errCreds := vertexCreds(auth)
				if errCreds != nil {
					t.Fatal(errCreds)
				}
				_, errToken := vertexAccessToken(ctx, &config.Config{}, auth, raw)
				if errToken == nil || !strings.Contains(errToken.Error(), "connection refused") {
					t.Fatalf("synthetic token diagnostic not reached: %v", errToken)
				}
				if diagnostic.name == "token-and-error-sequence" && !strings.Contains(errToken.Error(), "synthetic-access-secret") {
					t.Fatalf("synthetic leak marker missing from raw error: %v", errToken)
				}

				req := cliproxyexecutor.Request{Model: "gemini-2.5-flash", Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"synthetic"}]}]}`)}
				opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini, Stream: path.stream}
				if path.interactions {
					opts.SourceFormat = sdktranslator.FormatInteractions
					req.Payload = []byte(`{"model":"gemini-2.5-flash","input":"synthetic"}`)
				}
				e := NewGeminiVertexExecutor(&config.Config{})
				var err error
				if path.stream {
					var result *cliproxyexecutor.StreamResult
					result, err = e.ExecuteStream(ctx, auth, req, opts)
					if result != nil {
						t.Fatal("token failure returned a stream")
					}
				} else {
					var response cliproxyexecutor.Response
					if path.count {
						response, err = e.CountTokens(ctx, auth, req, opts)
					} else {
						response, err = e.Execute(ctx, auth, req, opts)
					}
					if len(response.Payload) != 0 {
						t.Fatal("token failure returned a response payload")
					}
				}
				var status statusErr
				if !errors.As(err, &status) || status.StatusCode() != http.StatusInternalServerError || status.Error() != "internal server error" {
					t.Fatalf("downstream error = %v, want unchanged generic 500", err)
				}
				prefix := "vertex executor: access token error: "
				if path.interactions {
					prefix = "vertex executor: interactions access token error: "
				}
				line := output.String()
				if !strings.Contains(line, prefix+"connection_refused") {
					t.Fatalf("safe failure signal missing: %q", line)
				}
				for _, forbidden := range []string{"synthetic-access-secret", "synthetic-refresh-secret", "synthetic-bearer-secret", "UNLABELED-SECRET", "injected-error-sequence", "unknown credential type", "\\x1b", "\x1b"} {
					if strings.Contains(line, forbidden) {
						t.Errorf("log leaked %q: %q", forbidden, line)
					}
				}
				if attempts != 0 {
					t.Fatalf("unexpected HTTP attempts = %d, want zero", attempts)
				}
			})
		}
	}
}
