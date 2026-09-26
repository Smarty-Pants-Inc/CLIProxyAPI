package claude

import (
	"context"
	"errors"
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

type messageIDExecutor struct{}

func (e *messageIDExecutor) Identifier() string { return "test-provider" }

func (e *messageIDExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{Payload: []byte(`{"id":"msg_upstream1","type":"message","role":"assistant","content":[]}`)}, nil
}

func (e *messageIDExecutor) ExecuteStream(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, errors.New("not implemented")
}

func (e *messageIDExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (e *messageIDExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (e *messageIDExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

// The request log line records compact=yes for an on-demand summary request
// and compact=no for an ordinary request that carries the same beta header,
// as Pi sends after a compaction (smarty-dev#933).
func TestClaudeMessagesLogLineCompactionFlag(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &messageIDExecutor{}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "auth-claude-log-ids", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatalf("Register auth: %v", err)
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "test-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	h := NewClaudeCodeAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
	router := gin.New()
	router.Use(logging.GinLogrusLogger())
	router.POST("/v1/messages", h.ClaudeMessages)

	for _, tc := range []struct {
		name, extra, want string
	}{
		{"summary request", `,"compaction":{"type":"summarize"}`, "compact=yes"},
		{"ordinary with beta", ``, "compact=no"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := logtest.NewLocal(log.StandardLogger())
			defer hook.Reset()
			body := `{"model":"test-model","max_tokens":16,"messages":[{"role":"user","content":"hi"}]` + tc.extra + `}`
			req := httptest.NewRequest(http.MethodPost, "/v1/messages?beta=true", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Anthropic-Beta", "compact-2026-09-04")
			req.Header.Set("X-Session-Affinity", "01a0cdab-6295-73b9")
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)
			if resp.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", resp.Code, resp.Body.String())
			}
			want := "| session=01a0cdab-6295-73b9 msg=msg_upstream1 " + tc.want
			for _, entry := range hook.AllEntries() {
				if strings.HasSuffix(entry.Message, want) {
					return
				}
			}
			t.Fatalf("no log line ends with %q", want)
		})
	}
}
