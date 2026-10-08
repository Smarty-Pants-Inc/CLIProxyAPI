package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	claudehandlers "github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers/claude"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

func TestClaudeExecutorFastHTTPErrorPassesThroughWithoutRetry(t *testing.T) {
	testCases := []struct {
		name       string
		status     int
		stream     bool
		oauth      bool
		compressed bool
		betaOnly   bool
	}{
		{name: "non-stream OAuth bad request", status: http.StatusBadRequest, oauth: true},
		{name: "stream OAuth unauthorized", status: http.StatusUnauthorized, stream: true, oauth: true},
		{name: "non-stream API key forbidden", status: http.StatusForbidden},
		{name: "stream OAuth credits refusal", status: http.StatusTooManyRequests, stream: true, oauth: true, compressed: true},
		{name: "non-stream OAuth server error", status: http.StatusInternalServerError, oauth: true},
		{name: "stream OAuth beta-only Fast refusal", status: http.StatusServiceUnavailable, stream: true, oauth: true, betaOnly: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var attempts atomic.Int32
			const errorJSON = `{"type":"error","error":{"type":"upstream_error","message":"Fast request rejected"}}`
			transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				attempts.Add(1)
				requestBody, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					t.Fatal(errRead)
				}
				if !testCase.betaOnly && !bytes.Contains(requestBody, []byte(`"speed":"fast"`)) {
					t.Fatalf("upstream request does not contain speed=fast: %s", requestBody)
				}
				if testCase.betaOnly && bytes.Contains(requestBody, []byte(`"speed"`)) {
					t.Fatalf("beta-only Fast request unexpectedly gained speed: %s", requestBody)
				}
				var wireBetas string
				for name, values := range req.Header {
					if strings.EqualFold(name, "Anthropic-Beta") {
						wireBetas = strings.Join(values, ",")
						break
					}
				}
				if !strings.Contains(wireBetas, claudeFastModeBeta) {
					t.Fatalf("upstream request is missing %s", claudeFastModeBeta)
				}

				body := []byte(errorJSON)
				headers := http.Header{"Content-Type": []string{"application/json"}}
				if testCase.compressed {
					var compressed bytes.Buffer
					writer := gzip.NewWriter(&compressed)
					if _, errWrite := writer.Write(body); errWrite != nil {
						t.Fatal(errWrite)
					}
					if errClose := writer.Close(); errClose != nil {
						t.Fatal(errClose)
					}
					body = compressed.Bytes()
					headers.Set("Content-Encoding", "gzip")
				}
				return &http.Response{
					StatusCode: testCase.status,
					Header:     headers,
					Body:       io.NopCloser(bytes.NewReader(body)),
					Request:    req,
				}, nil
			})

			ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
			auth := &cliproxyauth.Auth{ID: "fast-error-test", Metadata: claudeOAuthTestMetadata()}
			if testCase.oauth {
				auth.Attributes = map[string]string{"api_key": "sk-ant-oat-fast-error"}
			} else {
				auth.Attributes = map[string]string{"api_key": "sk-ant-api03-fast-error"}
				auth.Metadata = nil
			}
			requestPayload := []byte(`{"model":"claude-opus-5","max_tokens":16,"speed":"fast","messages":[{"role":"user","content":"reply OK"}]}`)
			options := cliproxyexecutor.Options{
				Stream:         testCase.stream,
				SourceFormat:   sdktranslator.FormatClaude,
				ResponseFormat: sdktranslator.FormatClaude,
			}
			if testCase.betaOnly {
				requestPayload = []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"reply OK"}]}`)
				options.Headers = http.Header{"Anthropic-Beta": []string{claudeFastModeBeta}}
			}
			request := cliproxyexecutor.Request{Model: "claude-opus-5", Payload: requestPayload}

			executor := NewClaudeExecutor(&config.Config{})
			var errExecute error
			if testCase.stream {
				_, errExecute = executor.ExecuteStream(ctx, auth, request, options)
			} else {
				_, errExecute = executor.Execute(ctx, auth, request, options)
			}
			if errExecute == nil {
				t.Fatal("Fast request error = nil")
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("upstream attempts = %d, want 1", got)
			}
			var direct *cliproxyexecutor.RequestTerminatedError
			if !errors.As(errExecute, &direct) || direct == nil {
				t.Fatalf("error = %T %v, want direct response", errExecute, errExecute)
			}
			if got := direct.StatusCode(); got != testCase.status {
				t.Fatalf("direct status = %d, want %d", got, testCase.status)
			}
			if got := string(direct.ResponseBody()); got != errorJSON {
				t.Fatalf("direct body = %q, want %q", got, errorJSON)
			}
			if got := direct.ResponseHeaders().Get("Content-Encoding"); got != "" {
				t.Fatalf("direct Content-Encoding = %q, want absent after decode", got)
			}
			requestScoped, ok := errExecute.(cliproxyexecutor.RequestScopedError)
			if !ok || !requestScoped.IsRequestScoped() {
				t.Fatalf("Fast direct response error = %T, want request-scoped", errExecute)
			}
		})
	}
}

func TestClaudeExecutorFastSuccessfulHTTPDecodeErrorDoesNotExposeSuccessStatus(t *testing.T) {
	testCases := []struct {
		name string
		run  func(context.Context, *ClaudeExecutor, *cliproxyauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) error
	}{
		{
			name: "execute",
			run: func(ctx context.Context, executor *ClaudeExecutor, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) error {
				_, errExecute := executor.Execute(ctx, auth, req, opts)
				return errExecute
			},
		},
		{
			name: "stream",
			run: func(ctx context.Context, executor *ClaudeExecutor, auth *cliproxyauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) error {
				_, errStream := executor.ExecuteStream(ctx, auth, req, opts)
				return errStream
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var attempts atomic.Int32
			transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				attempts.Add(1)
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}},
					Body:       io.NopCloser(strings.NewReader("not-a-gzip-stream")),
					Request:    req,
				}, nil
			})
			ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
			auth := &cliproxyauth.Auth{
				ID:         "fast-success-decode-error",
				Attributes: map[string]string{"api_key": "sk-ant-oat-fast-success-decode-error"},
				Metadata:   claudeOAuthTestMetadata(),
			}
			request := cliproxyexecutor.Request{
				Model:   "claude-opus-5",
				Payload: []byte(`{"model":"claude-opus-5","max_tokens":16,"speed":"fast","messages":[{"role":"user","content":"reply OK"}]}`),
			}
			errRun := testCase.run(ctx, NewClaudeExecutor(&config.Config{}), auth, request, cliproxyexecutor.Options{
				Stream:         testCase.name == "stream",
				SourceFormat:   sdktranslator.FormatClaude,
				ResponseFormat: sdktranslator.FormatClaude,
			})
			if errRun == nil {
				t.Fatal("Fast decode error = nil")
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("upstream attempts = %d, want 1", got)
			}
			var requestErr cliproxyexecutor.RequestScopedError
			if !errors.As(errRun, &requestErr) || requestErr == nil || !requestErr.IsRequestScoped() {
				t.Fatalf("Fast decode error = %T %v, want request-scoped", errRun, errRun)
			}
			var statusErr interface{ StatusCode() int }
			if !errors.As(errRun, &statusErr) || statusErr == nil {
				t.Fatalf("Fast decode error = %T %v, want status provider", errRun, errRun)
			}
			if got := statusErr.StatusCode(); got != 0 {
				t.Fatalf("Fast decode status = %d, want 0 instead of upstream success", got)
			}
		})
	}
}

func TestClaudeExecutorFastTransportErrorIsRequestScopedWithoutRetry(t *testing.T) {
	upstreamErr := errors.New("transport unavailable")
	var attempts atomic.Int32
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		attempts.Add(1)
		return nil, upstreamErr
	})
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
	auth := &cliproxyauth.Auth{
		ID:         "fast-transport-error",
		Attributes: map[string]string{"api_key": "sk-ant-oat-fast-transport"},
		Metadata:   claudeOAuthTestMetadata(),
	}
	request := cliproxyexecutor.Request{
		Model:   "claude-opus-5",
		Payload: []byte(`{"model":"claude-opus-5","max_tokens":16,"speed":"fast","messages":[{"role":"user","content":"reply OK"}]}`),
	}

	_, errExecute := NewClaudeExecutor(&config.Config{}).Execute(ctx, auth, request, cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FormatClaude,
		ResponseFormat: sdktranslator.FormatClaude,
	})
	if !errors.Is(errExecute, upstreamErr) {
		t.Fatalf("error = %v, want wrapped transport error", errExecute)
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("upstream attempts = %d, want 1", got)
	}
	requestScoped, ok := errExecute.(cliproxyexecutor.RequestScopedError)
	if !ok || !requestScoped.IsRequestScoped() {
		t.Fatalf("Fast transport error = %T, want request-scoped", errExecute)
	}
}

func TestClaudeExecutorFastNonStreamPreIdentityOverloadDoesNotRotateOrCool(t *testing.T) {
	const model = "claude-opus-5-5"
	var attempts atomic.Int32
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		if !isAnthropicUpstreamURL(req.URL) || !claudeRequestIsFast(req, body) || !gjson.GetBytes(body, "stream").Bool() {
			t.Fatalf("expected Fast Anthropic upstream SSE request, got %s: %s", req.URL, body)
		}
		if got := gjson.GetBytes(body, "model").String(); got != model {
			t.Fatalf("upstream model = %q, want %q", got, model)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body:       io.NopCloser(strings.NewReader("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"MUST_NOT_LEAK\"}}\n\n")),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
	cfg := &config.Config{DisableCooling: false}
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 2)
	manager.RegisterExecutor(NewClaudeExecutor(cfg))
	reg := registry.GetGlobalRegistry()
	credentials := []*cliproxyauth.Auth{
		{ID: t.Name() + "-1", Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant-api03-synthetic-1"}},
		{ID: t.Name() + "-2", Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant-api03-synthetic-2"}},
	}
	for _, credential := range credentials {
		reg.RegisterClient(credential.ID, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(credential.ID) })
		if _, errRegister := manager.Register(ctx, credential); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	response, errExecute := manager.Execute(ctx, []string{"claude"}, cliproxyexecutor.Request{
		Model:   model,
		Payload: []byte(`{"model":"claude-opus-5-5","max_tokens":16,"speed":"fast","messages":[{"role":"user","content":"reply OK"}]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatClaude, ResponseFormat: sdktranslator.FormatOpenAI})
	if got := attempts.Load(); got != 1 {
		t.Errorf("upstream attempts = %d, want exactly 1 (no credential rotation)", got)
	}
	var statusErr interface{ StatusCode() int }
	if !errors.As(errExecute, &statusErr) || statusErr.StatusCode() != http.StatusBadGateway {
		t.Errorf("error = %T %v, want status 502", errExecute, errExecute)
	}
	var requestErr cliproxyexecutor.RequestScopedError
	if !errors.As(errExecute, &requestErr) || !requestErr.IsRequestScoped() {
		t.Errorf("error = %T %v, want request scope", errExecute, errExecute)
	}
	if errExecute == nil || errExecute.Error() != "overloaded_error: upstream overloaded" || len(response.Payload) != 0 {
		t.Errorf("want sanitized overload without output, got payload=%q error=%v", response.Payload, errExecute)
	}
	for _, credential := range credentials {
		registered, ok := manager.GetByID(credential.ID)
		if !ok || registered == nil {
			t.Fatalf("credential %q not found", credential.ID)
		}
		if registered.Unavailable || !registered.NextRetryAfter.IsZero() || registered.Quota.Exceeded || !registered.Quota.NextRecoverAt.IsZero() {
			t.Errorf("credential %q cooled: unavailable=%t retry=%v quota=%+v", credential.ID, registered.Unavailable, registered.NextRetryAfter, registered.Quota)
		}
		for name, state := range registered.ModelStates {
			if state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded || !state.Quota.NextRecoverAt.IsZero()) {
				t.Errorf("credential %q model %q cooled: %+v", credential.ID, name, state)
			}
		}
	}
}

func TestClaudeExecutorFastStreamPreIdentityOverloadDoesNotRotateOrCool(t *testing.T) {
	const model = "claude-opus-5-5"
	var attempts atomic.Int32
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Fatal(errRead)
		}
		if !isAnthropicUpstreamURL(req.URL) || !claudeRequestIsFast(req, body) || !gjson.GetBytes(body, "stream").Bool() {
			t.Fatalf("expected Fast Anthropic upstream SSE request, got %s: %s", req.URL, body)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
			Body: io.NopCloser(strings.NewReader("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"MUST_NOT_LEAK\"}}\n\n" +
				"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"MUST_NOT_LEAK\"}}\n\n")),
			Request: req,
		}, nil
	})
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
	cfg := &config.Config{DisableCooling: false}
	cfg.Claude.ModelLevelCooling = true
	manager := cliproxyauth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 2)
	manager.RegisterExecutor(NewClaudeExecutor(cfg))
	reg := registry.GetGlobalRegistry()
	credentials := []*cliproxyauth.Auth{
		{ID: t.Name() + "-1", Provider: "claude", Attributes: map[string]string{"api_key": "[REDACTED:api-key]"}},
		{ID: t.Name() + "-2", Provider: "claude", Attributes: map[string]string{"api_key": "[REDACTED:api-key]"}},
	}
	for _, credential := range credentials {
		reg.RegisterClient(credential.ID, "claude", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { reg.UnregisterClient(credential.ID) })
		if _, errRegister := manager.Register(ctx, credential); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	handler := claudehandlers.NewClaudeCodeAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager))
	data, _, errs := handler.ExecuteStreamWithAuthManager(ctx, "claude", model, []byte(`{"model":"claude-opus-5-5","stream":true,"max_tokens":16,"speed":"fast","messages":[{"role":"user","content":"reply OK"}]}`), "")
	if data != nil {
		for chunk := range data {
			t.Errorf("unverified stream payload reached client: %q", chunk)
		}
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	var errorCount int
	for errMsg := range errs {
		errorCount++
		handler.WriteErrorResponse(c, errMsg)
	}
	if errorCount != 1 {
		t.Errorf("client errors = %d, want exactly 1", errorCount)
	}
	if recorder.Code != http.StatusBadGateway {
		t.Errorf("client status = %d, want 502", recorder.Code)
	}
	const wantBody = `{"type":"error","error":{"type":"api_error","message":"overloaded_error: upstream overloaded"}}`
	if got := recorder.Body.String(); got != wantBody || recorder.Header().Get("Content-Type") != "application/json" {
		t.Errorf("client body = %q, content-type = %q, want sanitized JSON %q", got, recorder.Header().Get("Content-Type"), wantBody)
	}
	if got := attempts.Load(); got != 1 {
		t.Errorf("upstream attempts = %d, want exactly 1 (no credential rotation)", got)
	}
	for _, credential := range credentials {
		registered, ok := manager.GetByID(credential.ID)
		if !ok || registered == nil {
			t.Fatalf("credential %q not found", credential.ID)
		}
		if registered.Unavailable || !registered.NextRetryAfter.IsZero() || registered.Quota.Exceeded || !registered.Quota.NextRecoverAt.IsZero() {
			t.Errorf("credential %q cooled: %+v", credential.ID, registered)
		}
		for name, state := range registered.ModelStates {
			if state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded || !state.Quota.NextRecoverAt.IsZero()) {
				t.Errorf("credential %q model %q cooled: %+v", credential.ID, name, state)
			}
		}
	}
}

func TestClaudeExecutorNonFastErrorKeepsCredentialScopedBehavior(t *testing.T) {
	var attempts atomic.Int32
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"type":"error","error":{"type":"rate_limit_error","message":"rate limit exceeded"}}`)),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", http.RoundTripper(transport))
	auth := &cliproxyauth.Auth{
		ID:         "standard-rate-limit",
		Attributes: map[string]string{"api_key": "sk-ant-oat-standard-rate-limit"},
		Metadata:   claudeOAuthTestMetadata(),
	}
	request := cliproxyexecutor.Request{
		Model:   "claude-opus-5",
		Payload: []byte(`{"model":"claude-opus-5","max_tokens":16,"messages":[{"role":"user","content":"reply OK"}]}`),
	}

	_, errExecute := NewClaudeExecutor(&config.Config{}).Execute(ctx, auth, request, cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FormatClaude,
		ResponseFormat: sdktranslator.FormatClaude,
	})
	var statusError interface{ StatusCode() int }
	if !errors.As(errExecute, &statusError) || statusError.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("error = %v, want status 429", errExecute)
	}
	var direct *cliproxyexecutor.RequestTerminatedError
	if errors.As(errExecute, &direct) {
		t.Fatal("non-Fast error unexpectedly became a direct response")
	}
	if requestScoped, ok := errExecute.(cliproxyexecutor.RequestScopedError); ok && requestScoped.IsRequestScoped() {
		t.Fatal("non-Fast rate limit unexpectedly became request-scoped")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("upstream attempts = %d, want 1", got)
	}
}
