package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Exercise the public HTTP bootstrap API and the production direct-response
// writer with two credentials. A one-credential fixture misses inner failover.
func TestHandlerTerminalRound3StreamPreservesFirstHTTPResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, status := range []int{http.StatusOK, http.StatusTooManyRequests} {
		for _, laterTerminates := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/later-terminal-%t", status, laterTerminates), func(t *testing.T) {
				model := fmt.Sprintf("handler-terminal-r3-%d-%t", status, laterTerminates)
				executorCalls := 0
				executor := &interceptorCaptureExecutor{stream: func(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
					executorCalls++
					chunks := make(chan coreexecutor.StreamChunk, 1)
					chunks <- coreexecutor.StreamChunk{Payload: []byte("data: {\"unexpected\":true}\n\n")}
					close(chunks)
					return &coreexecutor.StreamResult{Chunks: chunks}, nil
				}}
				handler := newInterceptorHandler(t, model, executor, &sdkconfig.SDKConfig{})
				handler.AuthManager.SetRetryConfig(0, 0, 0)
				secondID := "handler-terminal-second-" + model
				if _, err := handler.AuthManager.Register(context.Background(), &coreauth.Auth{ID: secondID, Provider: "codex", Status: coreauth.StatusActive}); err != nil { t.Fatal(err) }
				registry.GetGlobalRegistry().RegisterClient(secondID, "codex", []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(secondID) })
				ids := []string{"handler-interceptor-"+model, secondID}
				before := make(map[string]*coreauth.Auth)
				for _, id := range ids { before[id], _ = handler.AuthManager.GetByID(id) }
				afterCalls, completions := 0, 0
				var completion pluginapi.RequestCompletion
				var firstRequestID string
				body := "original direct response\n"
				handler.SetPluginHost(&handlerInterceptorTestHost{
					interceptRequestAfterAuth: func(_ context.Context, in pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
						afterCalls++
						if afterCalls == 1 {
							firstRequestID = in.RequestID
							return pluginapi.RequestInterceptResponse{Terminate: true, StatusCode: status, ResponseHeaders: http.Header{"Content-Type": {"text/plain"}, "X-Terminal": {"first", "retained"}, "Retry-After": {"7"}}, ResponseBody: []byte(body)}
						}
						return pluginapi.RequestInterceptResponse{Terminate: laterTerminates, StatusCode: http.StatusForbidden, ResponseBody: []byte("replacement response")}
					},
					completeRequest: func(_ context.Context, got pluginapi.RequestCompletion) { completions++; completion = got },
				})
				recorder := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(recorder)
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"`+model+`","input":[],"stream":true}`))
				ctx := context.WithValue(c.Request.Context(), "gin", c)
				data, headers, errs := handler.ExecuteStreamWithAuthManager(ctx, "openai-response", model, []byte(`{"model":"`+model+`","input":[],"stream":true}`), "")
				if data != nil || headers != nil { t.Error("terminal bootstrap exposed a data stream or upstream headers") }
				select {
				case msg, ok := <-errs:
					if !ok || msg == nil { t.Fatal("missing terminal response") }
					if !msg.DirectResponse || msg.StatusCode != status || string(msg.Body) != body { t.Errorf("bootstrap response = %+v", msg) }
					handler.WriteErrorResponse(c, msg)
				case <-time.After(time.Second):
					t.Fatal("terminal bootstrap did not return its direct response")
				}
				if recorder.Code != status || recorder.Body.String() != body || recorder.Header().Get("Content-Type") != "text/plain" || recorder.Header().Get("Retry-After") != "7" || !reflect.DeepEqual(recorder.Header().Values("X-Terminal"), []string{"first", "retained"}) { t.Errorf("HTTP response changed: status=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String()) }
				if afterCalls != 1 || executorCalls != 0 || completions != 1 { t.Errorf("after-auth=%d executor=%d completions=%d, want 1/0/1", afterCalls, executorCalls, completions) }
				if completion.Outcome != pluginapi.RequestCompletionRejected || completion.RequestID != firstRequestID || completion.StatusCode != status { t.Errorf("completion=%+v", completion) }
				if ctx.Err() != nil { t.Error("terminal response canceled HTTP parent") }
				for _, id := range ids {
					a, _ := handler.AuthManager.GetByID(id)
					if a.Unavailable || !a.NextRetryAfter.IsZero() || a.LastError != nil || !reflect.DeepEqual(a.ModelStates, before[id].ModelStates) { t.Errorf("terminal HTTP response changed cooldown for %s: %+v", id, a) }
				}
			})
		}
	}
}
