package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	initialFailureChatModel = "initial-failure-chat-model"
)

type initialFailureStreamExecutor struct{}

func (*initialFailureStreamExecutor) Identifier() string { return "initial-failure-stream-executor" }

func (*initialFailureStreamExecutor) Execute(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (*initialFailureStreamExecutor) ExecuteStream(_ context.Context, _ *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	chunks := make(chan coreexecutor.StreamChunk, 1)
	chunks <- coreexecutor.StreamChunk{Err: errors.New("upstream failed before first payload")}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (*initialFailureStreamExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func (*initialFailureStreamExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (*initialFailureStreamExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func runOpenAIStreamErrorTest(t *testing.T, endpoint string, body string) {
	gin.SetMode(gin.TestMode)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			executor := &initialFailureStreamExecutor{}
			manager := coreauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(executor)
			authID := fmt.Sprintf("initial-failure-auth-%s-%d", strings.ReplaceAll(endpoint, "/", "-"), idx)
			auth := &coreauth.Auth{ID: authID, Provider: executor.Identifier(), Status: coreauth.StatusActive}
			if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
				t.Errorf("register auth %d: %v", idx, errRegister)
				return
			}
			registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: initialFailureChatModel}})
			defer registry.GetGlobalRegistry().UnregisterClient(auth.ID)

			base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager)
			h := NewOpenAIAPIHandler(base)
			router := gin.New()
			if endpoint == "/v1/chat/completions" {
				router.POST(endpoint, h.ChatCompletions)
			} else {
				router.POST(endpoint, h.Completions)
			}

			request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code == http.StatusOK {
				t.Errorf("[%s] request %d lost the buffered initial error and returned HTTP 200: %q", endpoint, idx, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "upstream failed before first payload") {
				t.Errorf("[%s] request %d lost the initial upstream error: status=%d body=%q", endpoint, idx, recorder.Code, recorder.Body.String())
			}
		}(i)
	}
	wg.Wait()
}

func TestChatCompletionsHandlerDoesNotLoseErrorBeforeFirstPayload(t *testing.T) {
	runOpenAIStreamErrorTest(t, "/v1/chat/completions", `{"model":"initial-failure-chat-model","messages":[{"role":"user","content":"hi"}],"stream":true}`)
}

func TestCompletionsHandlerDoesNotLoseErrorBeforeFirstPayload(t *testing.T) {
	runOpenAIStreamErrorTest(t, "/v1/completions", `{"model":"initial-failure-chat-model","prompt":"hi","stream":true}`)
}

type droppedPrefixQuotaError struct {
	retryAfter time.Duration
}

func (*droppedPrefixQuotaError) Error() string                { return "quota after server-side work" }
func (*droppedPrefixQuotaError) StatusCode() int              { return http.StatusTooManyRequests }
func (e *droppedPrefixQuotaError) RetryAfter() *time.Duration { return &e.retryAfter }
func (*droppedPrefixQuotaError) IsCredentialScoped() bool     { return false }

type droppedPrefixStreamExecutor struct {
	initialFailureStreamExecutor
	failure error
	calls   atomic.Int32
}

func (e *droppedPrefixStreamExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	coreexecutor.MarkUpstreamAttempt(ctx)
	chunks := make(chan coreexecutor.StreamChunk, 2)
	if e.calls.Add(1) == 1 {
		chunks <- coreexecutor.StreamChunk{Payload: []byte(`{"type":"response.output_item.added","item":{"type":"web_search_call","status":"in_progress"}}`)}
		chunks <- coreexecutor.StreamChunk{Err: e.failure}
	} else {
		chunks <- coreexecutor.StreamChunk{Payload: []byte(`{"replacement":true}`)}
	}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

type droppedPrefixInterceptor struct {
	dropped int
}

func (*droppedPrefixInterceptor) InterceptRequestBeforeAuth(_ context.Context, req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body}
}

func (*droppedPrefixInterceptor) InterceptRequestAfterAuth(_ context.Context, req pluginapi.RequestInterceptRequest) pluginapi.RequestInterceptResponse {
	return pluginapi.RequestInterceptResponse{Headers: req.Headers, Body: req.Body}
}

func (*droppedPrefixInterceptor) InterceptResponse(_ context.Context, req pluginapi.ResponseInterceptRequest) pluginapi.ResponseInterceptResponse {
	return pluginapi.ResponseInterceptResponse{Headers: req.ResponseHeaders, Body: req.Body}
}

func (h *droppedPrefixInterceptor) InterceptStreamChunk(_ context.Context, req pluginapi.StreamChunkInterceptRequest) pluginapi.StreamChunkInterceptResponse {
	drop := strings.Contains(string(req.Body), "web_search_call")
	if drop {
		h.dropped++
	}
	return pluginapi.StreamChunkInterceptResponse{Body: req.Body, DropChunk: drop}
}

func TestChatCompletionsHandlerBootstrapRespectsNonReplayableStop(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, stop := range []bool{true, false} {
		name := "unmarked_quota_retries"
		if stop {
			name = "non_replayable_stop"
		}
		t.Run(name, func(t *testing.T) {
			model := "dropped-prefix-" + name
			quota := &droppedPrefixQuotaError{retryAfter: 17 * time.Second}
			var failure error = quota
			if stop {
				// Use the actual stop-only wrapper, not a request-scoped substitute.
				failure = fmt.Errorf("executor: %w", helps.WrapCodexNonReplayableStreamError(quota))
			}
			executor := &droppedPrefixStreamExecutor{failure: failure}
			manager := coreauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(executor)
			ids := []string{model + "-first", model + "-replacement"}
			for i, id := range ids {
				auth := &coreauth.Auth{ID: id, Provider: executor.Identifier(), Status: coreauth.StatusActive,
					Attributes: map[string]string{"priority": fmt.Sprint(10 - i)}}
				if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
					t.Fatal(errRegister)
				}
				registry.GetGlobalRegistry().RegisterClient(id, auth.Provider, []*registry.ModelInfo{{ID: model}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
			}
			base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{Streaming: sdkconfig.StreamingConfig{BootstrapRetries: 1}}, manager)
			interceptor := &droppedPrefixInterceptor{}
			base.SetPluginHost(interceptor)
			router := gin.New()
			router.POST("/v1/chat/completions", NewOpenAIAPIHandler(base).ChatCompletions)
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hi"}],"stream":true}`, model)))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			started := time.Now()
			router.ServeHTTP(recorder, request)

			if interceptor.dropped != 1 || strings.Contains(recorder.Body.String(), "web_search_call") {
				t.Errorf("dropped=%d body=%q: want unsafe prefix dropped once and withheld", interceptor.dropped, recorder.Body.String())
			}
			if stop {
				if got := executor.calls.Load(); got != 1 {
					t.Errorf("upstream attempts = %d, want 1 (hard stop must prevent replay)", got)
				}
				var response struct {
					Error struct{ Message string } `json:"error"`
				}
				if errDecode := json.Unmarshal(recorder.Body.Bytes(), &response); errDecode != nil || recorder.Code != http.StatusTooManyRequests || response.Error.Message != failure.Error() {
					t.Errorf("client error status=%d body=%q decode=%v, want original 429 %q", recorder.Code, recorder.Body.String(), errDecode, failure.Error())
				}
				if strings.Contains(recorder.Body.String(), "replacement") {
					t.Error("hard stop leaked replacement output")
				}
			} else if executor.calls.Load() != 2 || recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `{"replacement":true}`) {
				t.Errorf("unmarked quota must retry: calls=%d status=%d body=%q", executor.calls.Load(), recorder.Code, recorder.Body.String())
			}
			first, _ := manager.GetByID(ids[0])
			state := first.ModelStates[model]
			if state == nil || !state.Unavailable || !state.Quota.Exceeded || state.LastError == nil || state.LastError.HTTPStatus != http.StatusTooManyRequests || state.NextRetryAfter.Before(started.Add(quota.retryAfter)) || len(first.ModelStates) != 1 {
				t.Errorf("original quota/model cooldown not retained: %+v", state)
			}
			replacement, _ := manager.GetByID(ids[1])
			if replacement.Unavailable || !replacement.NextRetryAfter.IsZero() || replacement.Quota.Exceeded {
				t.Error("eligible replacement credential unexpectedly cooled down")
			}
		})
	}
}
