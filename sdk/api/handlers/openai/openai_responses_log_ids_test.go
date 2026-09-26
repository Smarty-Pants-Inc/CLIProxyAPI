package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type responsesIDExecutor struct{ compactCaptureExecutor }

func (e *responsesIDExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{Payload: []byte(`{"id":"resp_upstream1","object":"response","output":[]}`)}, nil
}

// The request log line records compact=yes only for a Codex compaction
// trigger, not for an ordinary Responses request (smarty-dev#933).
func TestOpenAIResponsesLogLineCompactionFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &responsesIDExecutor{}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "auth-log-ids", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "test-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	h := NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.Use(logging.GinLogrusLogger())
	router.POST("/v1/responses", h.Responses)

	for _, tc := range []struct {
		name, input, want string
	}{
		{"compaction trigger", `[{"type":"message","role":"user","content":"hi"},{"type":"compaction_trigger"}]`, "compact=yes"},
		{"ordinary", `[{"type":"message","role":"user","content":"hi"}]`, "compact=no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := logtest.NewLocal(log.StandardLogger())
			defer hook.Reset()
			req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"test-model","input":`+tc.input+`}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Session_id", "codex-thread-1")
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)
			if resp.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.Code, resp.Body.String())
			}
			want := "| session=codex-thread-1 msg=resp_upstream1 " + tc.want
			for _, entry := range hook.AllEntries() {
				if strings.HasSuffix(entry.Message, want) {
					return
				}
			}
			t.Fatalf("no log line ends with %q", want)
		})
	}
}
