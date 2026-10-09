package handlers_test

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	codexresponses "github.com/router-for-me/CLIProxyAPI/v8/internal/translator/codex/openai/responses"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// Unused executor operations are deliberately not mocked: this fixture follows
// the real Scanner -> translator -> Manager -> HTTP validator/framer path.
type multilineCompactionHTTPExecutor struct {
	coreauth.ProviderExecutor
	wire string
}

func (*multilineCompactionHTTPExecutor) Identifier() string { return "codex" }
func (e *multilineCompactionHTTPExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	chunks := make(chan coreexecutor.StreamChunk)
	go func() {
		defer close(chunks)
		scanner := bufio.NewScanner(strings.NewReader(e.wire))
		var param any
		for scanner.Scan() {
			line := bytes.Clone(scanner.Bytes())
			for _, payload := range codexresponses.ConvertCodexResponseToOpenAIResponses(ctx, req.Model, opts.OriginalRequest, req.Payload, line, &param) {
				select {
				case chunks <- coreexecutor.StreamChunk{Payload: payload}:
				case <-ctx.Done():
					return
				}
			}
			// Hold before any completion or terminal error. Client Write must
			// establish persisted signer evidence while this barrier is held.
			if bytes.Contains(line, []byte("C_A")) {
				<-ctx.Done()
				return
			}
		}
	}()
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

type multilineCompactionWriter struct {
	*httptest.ResponseRecorder
	onSigned func()
}

func (w *multilineCompactionWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("C_A")) {
		w.onSigned()
	}
	return w.ResponseRecorder.Write(p)
}

func TestResponsesHandlerRegistersScannerMultilineBeforeClientDelivery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const model = "scanner-http-multiline-compaction"
	path := filepath.Join(t.TempDir(), "affinity.state")
	selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &coreauth.FillFirstSelector{}, StatePath: path})
	defer selector.Stop()
	manager := coreauth.NewManager(nil, selector, nil)
	executor := &multilineCompactionHTTPExecutor{wire: "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"model\":\"" + model + "\"}}\n\nevent: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\ndata: \"item\":{\"type\":\"compaction\",\"encrypted_content\":\"C_A\"}}\n\n"}
	manager.RegisterExecutor(executor)
	for _, id := range []string{"multiline-A", "multiline-B"} {
		if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive}); err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		defer registry.GetGlobalRegistry().UnregisterClient(id)
	}
	base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
	h := openai.NewOpenAIResponsesAPIHandler(base)
	router := gin.New()
	router.POST("/v1/responses", h.Responses)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+model+`","input":[],"stream":true}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	seen := false
	writer := &multilineCompactionWriter{ResponseRecorder: httptest.NewRecorder(), onSigned: func() {
		seen = true
		// Restart from disk BEFORE first replay, at the actual client write.
		restarted := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &coreauth.RoundRobinSelector{}, StatePath: path})
		defer restarted.Stop()
		picked, err := restarted.Pick(context.Background(), "codex", model, coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(`{"input":[{"type":"compaction","encrypted_content":"C_A"}]}`)}, manager.List())
		if err != nil || picked == nil || picked.ID != "multiline-A" {
			t.Errorf("client delivery preceded persisted A evidence: auth=%v err=%v", picked, err)
		}
		cancel()
	}}
	router.ServeHTTP(writer, request)
	if !seen || writer.Code != http.StatusOK || !strings.Contains(writer.Body.String(), "event: response.output_item.done") {
		t.Fatalf("multiline handler delivery: seen=%v status=%d body=%q", seen, writer.Code, writer.Body.String())
	}
}
