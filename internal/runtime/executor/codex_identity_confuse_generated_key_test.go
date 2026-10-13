package executor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// CLIProxyAPI#111 review: a prompt_cache_key the executor generates (from
// session metadata or the client API key) is remapped per credential like a
// client-supplied key, and responses restore it.

func assertGeneratedKeyIsolated(t *testing.T, generatedKey string, body []byte, headers http.Header, clientOutput string) {
	t.Helper()
	wantKey := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", generatedKey)
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != wantKey {
		t.Fatalf("upstream prompt_cache_key = %q, want credential-scoped %q (generated %q)", got, wantKey, generatedKey)
	}
	if got := headers.Get("Session-Id"); got != wantKey {
		t.Fatalf("upstream Session-Id = %q, want credential-scoped %q", got, wantKey)
	}
	if strings.Contains(string(body), generatedKey) {
		t.Fatalf("upstream body leaks the generated key %q: %s", generatedKey, body)
	}
	if headersContain(headers, generatedKey) {
		t.Fatalf("upstream headers leak the generated key %q: %v", generatedKey, headers)
	}
	if !strings.Contains(clientOutput, "key="+generatedKey) {
		t.Fatalf("client output does not carry the original generated key %q: %s", generatedKey, clientOutput)
	}
	if strings.Contains(clientOutput, wantKey) {
		t.Fatalf("client output leaks the credential-scoped key: %s", clientOutput)
	}
}

func TestCodexIdentityConfuseRemapsKeyGeneratedFromSessionMetadata(t *testing.T) {
	payload := []byte(`{"model":"gpt-5.5","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`)
	metadata := map[string]any{cliproxyexecutor.DerivedSessionIDMetadataKey: "ctx:v1:generated-key-root"}
	generatedKey := helps.ProviderSessionUUID("codex", metadata)
	if generatedKey == "" {
		t.Fatal("expected a generated session key from metadata")
	}

	t.Run("execute", func(t *testing.T) {
		capture := &identityTestCapture{}
		server := newIdentityHTTPServer(t, capture)
		exec := NewCodexExecutor(identityTestConfig(true))
		resp, err := exec.Execute(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
			Model: "gpt-5.5", Payload: payload, Metadata: metadata,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		body, headers := capture.snapshot()
		assertGeneratedKeyIsolated(t, generatedKey, body, headers, string(resp.Payload))
	})

	t.Run("stream", func(t *testing.T) {
		capture := &identityTestCapture{}
		server := newIdentityHTTPServer(t, capture)
		exec := NewCodexExecutor(identityTestConfig(true))
		result, err := exec.ExecuteStream(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
			Model: "gpt-5.5", Payload: payload, Metadata: metadata,
		}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, Stream: true})
		if err != nil {
			t.Fatalf("ExecuteStream: %v", err)
		}
		var out strings.Builder
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("stream chunk error: %v", chunk.Err)
			}
			out.Write(chunk.Payload)
		}
		body, headers := capture.snapshot()
		assertGeneratedKeyIsolated(t, generatedKey, body, headers, out.String())
	})
}

func TestCodexIdentityConfuseRemapsKeyGeneratedFromAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	ginCtx.Set("userApiKey", "generated-key-client-api-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	generatedKey := uuid.NewSHA1(uuid.NameSpaceOID, []byte("cli-proxy-api:codex:prompt-cache:generated-key-client-api-key")).String()

	capture := &identityTestCapture{}
	server := newIdentityHTTPServer(t, capture)
	exec := NewCodexExecutor(identityTestConfig(true))
	resp, err := exec.Execute(ctx, identityTestAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-5.5",
		Payload: []byte(`{"model":"gpt-5.5","messages":[{"role":"user","content":"hi"}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAI})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	body, headers := capture.snapshot()
	assertGeneratedKeyIsolated(t, generatedKey, body, headers, string(resp.Payload))
}

// Direct /images/* responses pass the upstream bytes through, so identifiers
// the upstream echoes must be restored before they reach the client.

func identityImageConfig() *config.Config {
	return &config.Config{
		Routing: config.RoutingConfig{SessionAffinity: true},
		Codex:   config.CodexConfig{IdentityConfuse: true},
	}
}

func newIdentityImageServer(t *testing.T, capture *identityTestCapture, stream bool) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("read upstream body: %v", errRead)
		}
		capture.mu.Lock()
		capture.body = body
		capture.headers = r.Header.Clone()
		capture.mu.Unlock()
		received := gjson.GetBytes(body, "prompt_cache_key").String()
		if stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: image_generation.completed\ndata: {\"type\":\"image_generation.completed\",\"b64_json\":\"BB==\",\"revised_prompt\":\"key=" + received + "\",\"usage\":{\"total_tokens\":10,\"input_tokens\":4,\"output_tokens\":6}}\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"created":1713833628,"data":[{"b64_json":"AA==","revised_prompt":"key=` + received + `"}],"usage":{"total_tokens":100,"input_tokens":50,"output_tokens":50}}`))
	}))
	t.Cleanup(server.Close)
	return server
}

func identityImageAuth(serverURL string) *cliproxyauth.Auth {
	auth := newCodexOpenAIImageTestAuth(serverURL)
	auth.ID = identityTestAuthID
	return auth
}

func identityImagePayload() []byte {
	return []byte(`{"model":"gpt-image-2","prompt":"A cute baby sea otter","prompt_cache_key":"` + identityTestCacheKey + `"}`)
}

func assertIdentityImageRoundTrip(t *testing.T, body []byte, clientOutput []byte) {
	t.Helper()
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != confused {
		t.Fatalf("upstream prompt_cache_key = %q, want credential-scoped %q; body=%s", got, confused, body)
	}
	if !bytes.Contains(clientOutput, []byte("key="+identityTestCacheKey)) {
		t.Fatalf("client image response does not carry the original identifier: %s", clientOutput)
	}
	if bytes.Contains(clientOutput, []byte(confused)) {
		t.Fatalf("client image response leaks the credential-scoped identifier: %s", clientOutput)
	}
}

func TestCodexIdentityConfuseDirectImageResponseRestoresIdentifiers(t *testing.T) {
	capture := &identityTestCapture{}
	server := newIdentityImageServer(t, capture, false)
	exec := NewCodexExecutor(identityImageConfig())
	resp, err := exec.Execute(context.Background(), identityImageAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-image-2",
		Payload: identityImagePayload(),
	}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	body, _ := capture.snapshot()
	assertIdentityImageRoundTrip(t, body, resp.Payload)
}

func TestCodexIdentityConfuseDirectImageStreamRestoresIdentifiers(t *testing.T) {
	capture := &identityTestCapture{}
	server := newIdentityImageServer(t, capture, true)
	exec := NewCodexExecutor(identityImageConfig())
	result, err := exec.ExecuteStream(context.Background(), identityImageAuth(server.URL), cliproxyexecutor.Request{
		Model:   "gpt-image-2",
		Payload: identityImagePayload(),
	}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	var out bytes.Buffer
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error: %v", chunk.Err)
		}
		out.Write(chunk.Payload)
	}
	body, _ := capture.snapshot()
	assertIdentityImageRoundTrip(t, body, out.Bytes())
}
