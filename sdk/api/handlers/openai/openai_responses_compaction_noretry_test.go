package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const compactionNoRetryResponsesModel = "compaction-noretry-responses-model"

// capturingResponsesExecutor answers every request and keeps the payload it was sent.
type capturingResponsesExecutor struct {
	mu       sync.Mutex
	payloads []string
}

func (*capturingResponsesExecutor) Identifier() string { return "compaction-degrade-responses" }

func (e *capturingResponsesExecutor) record(req coreexecutor.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.payloads = append(e.payloads, string(req.Payload))
}

func (e *capturingResponsesExecutor) last() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.payloads) == 0 {
		return ""
	}
	return e.payloads[len(e.payloads)-1]
}

func (e *capturingResponsesExecutor) Execute(_ context.Context, _ *coreauth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.record(req)
	return coreexecutor.Response{Payload: []byte(`{"id":"resp-1","object":"response","status":"completed","output":[]}`)}, nil
}

func (e *capturingResponsesExecutor) ExecuteStream(_ context.Context, _ *coreauth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.record(req)
	chunks := make(chan coreexecutor.StreamChunk, 1)
	chunks <- coreexecutor.StreamChunk{Payload: []byte("event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\",\"status\":\"completed\",\"output\":[]}}\n\n")}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (*capturingResponsesExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (*capturingResponsesExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (*capturingResponsesExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// smarty-dev#8742: a signed compaction block whose signer the gateway does not
// know (state lost or never recorded), and compaction input over the 16 MiB
// parsing cap, used to end the request with a hard 409 / 400 and
// x-should-retry: false. The request is now served with the block removed.
func TestResponsesUnknownOrOversizeCompactionIsServedWithoutTheBlock(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &capturingResponsesExecutor{}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	selector := coreauth.NewSessionAffinitySelector(&coreauth.FillFirstSelector{})
	defer selector.Stop()
	manager.SetSelector(selector)
	auth := &coreauth.Auth{ID: "compaction-noretry-responses-auth", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: compactionNoRetryResponsesModel}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
	h := NewOpenAIResponsesAPIHandler(base)
	router := gin.New()
	router.POST("/v1/responses", h.Responses)

	// smarty-dev#8742 security r1: a body over the hard input bound is refused with
	// 413 while it is read, before any JSON parse, and never reaches an executor.
	before := len(executor.payloads)
	for _, path := range []string{"/v1/responses"} {
		huge := `{"model":"` + compactionNoRetryResponsesModel + `","input":[{"role":"user","content":"` + strings.Repeat("A", coreauth.MaxCompactionInputBytes) + `"}]}`
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(huge))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusRequestEntityTooLarge || len(executor.payloads) != before {
			t.Fatalf("%s over the input bound: status %d, executor calls %d; want 413 and none", path, recorder.Code, len(executor.payloads)-before)
		}
	}

	blocks := map[string]string{
		"unknown-signer": "never-recorded-signer",
		"over-16MiB-cap": strings.Repeat("A", 17<<20),
	}
	for name, content := range blocks {
		for _, stream := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/non-streaming", true: "/streaming"}[stream], func(t *testing.T) {
				streamField := "false"
				if stream {
					streamField = "true"
				}
				body := `{"model":"` + compactionNoRetryResponsesModel + `","stream":` + streamField + `,"input":[{"type":"compaction","encrypted_content":"` + content + `"},{"role":"user","content":"continue"}]}`
				request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)

				if recorder.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200; body=%.300s", recorder.Code, recorder.Body.String())
				}
				sent := executor.last()
				if strings.Contains(sent, `"compaction"`) || !strings.Contains(sent, "continue") {
					t.Fatalf("upstream payload kept the block or lost the turn: %.300s", sent)
				}
				if strings.Contains(recorder.Body.String(), "compaction_affinity_missing") || strings.Contains(recorder.Body.String(), "compaction_json_rejected") {
					t.Fatalf("refusal in body: %.300s", recorder.Body.String())
				}
			})
		}
	}
}
