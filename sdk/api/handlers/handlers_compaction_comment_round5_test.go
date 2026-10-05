package handlers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// F2 end to end: Scanner -> translator -> Manager observer -> HTTP validator and
// framer. A legal SSE comment between the data lines of one multiline event
// must not abort the stream, and the client must receive the whole event.
func TestResponsesHandlerScannerCommentInsideMultilineEvent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const model = "scanner-http-multiline-comment"
	selector := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{Fallback: &coreauth.FillFirstSelector{}, StatePath: filepath.Join(t.TempDir(), "affinity.state")})
	defer selector.Stop()
	manager := coreauth.NewManager(nil, selector, nil)
	manager.RegisterExecutor(&multilineCompactionHTTPExecutor{wire: "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r5\",\"model\":\"" + model + "\"}}\n\n" +
		"data: {\"type\":\"response.output_item.done\",\n: keepalive\ndata: \"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_r5\",\"content\":[]}}\n\n" +
		"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r5\",\"model\":\"" + model + "\",\"status\":\"completed\",\"output\":[]}}\n\n"})
	const id = "multiline-comment-A"
	if _, err := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	defer registry.GetGlobalRegistry().UnregisterClient(id)
	router := gin.New()
	router.POST("/v1/responses", openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)).Responses)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+model+`","input":[],"stream":true}`)).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	writer := httptest.NewRecorder()
	router.ServeHTTP(writer, request)
	body := writer.Body.String()
	if writer.Code != http.StatusOK || !strings.Contains(body, `"msg_r5"`) || !strings.Contains(body, "response.completed") ||
		strings.Contains(body, "affinity_state") || strings.Contains(body, "event: error") {
		t.Fatalf("comment inside multiline event broke the stream: status=%d body=%q", writer.Code, body)
	}
}
