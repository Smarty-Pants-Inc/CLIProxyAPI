package logging

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestGinLogrusRecoveryRepanicsErrAbortHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(GinLogrusRecovery())
	engine.GET("/abort", func(c *gin.Context) {
		panic(http.ErrAbortHandler)
	})

	req := httptest.NewRequest(http.MethodGet, "/abort", nil)
	recorder := httptest.NewRecorder()

	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatalf("expected panic, got nil")
		}
		err, ok := recovered.(error)
		if !ok {
			t.Fatalf("expected error panic, got %T", recovered)
		}
		if !errors.Is(err, http.ErrAbortHandler) {
			t.Fatalf("expected ErrAbortHandler, got %v", err)
		}
		if err != http.ErrAbortHandler {
			t.Fatalf("expected exact ErrAbortHandler sentinel, got %v", err)
		}
	}()

	engine.ServeHTTP(recorder, req)
}

func TestGinLogrusRecoveryHandlesRegularPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(GinLogrusRecovery())
	engine.GET("/panic", func(c *gin.Context) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	recorder := httptest.NewRecorder()

	engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
}

func TestIsAIAPIPathIncludesPublicAPIGroups(t *testing.T) {
	for _, path := range []string{
		"/v1",
		"/v1/models",
		"/v1/alpha/search",
		"/v1beta/interactions",
		"/openai/v1/videos",
		"/backend-api/codex/responses",
	} {
		if !isAIAPIPath(path) {
			t.Fatalf("expected %s to be treated as AI API path", path)
		}
	}
	for _, path := range []string{
		"/v0/management/config",
		"/v10/models",
		"/openai/v10/videos",
		"/backend-api/codex-status",
	} {
		if isAIAPIPath(path) {
			t.Fatalf("expected %s not to be treated as AI API path", path)
		}
	}
}

func TestIsAIAPIPathIncludesImages(t *testing.T) {
	if !isAIAPIPath("/v1/images/generations") {
		t.Fatalf("expected /v1/images/generations to be treated as AI API path")
	}
	if !isAIAPIPath("/v1/images/edits") {
		t.Fatalf("expected /v1/images/edits to be treated as AI API path")
	}
	if !isAIAPIPath("/v1/videos") {
		t.Fatalf("expected /v1/videos to be treated as AI API path")
	}
	if !isAIAPIPath("/v1/videos/video_123") {
		t.Fatalf("expected /v1/videos/video_123 to be treated as AI API path")
	}
	if !isAIAPIPath("/openai/v1/videos") {
		t.Fatalf("expected /openai/v1/videos to be treated as AI API path")
	}
	if !isAIAPIPath("/openai/v1/videos/video_123/content") {
		t.Fatalf("expected /openai/v1/videos/video_123/content to be treated as AI API path")
	}
}

func TestIsAIAPIPathIncludesCodexBackend(t *testing.T) {
	paths := []string{
		"/backend-api/codex/responses",
		"/backend-api/codex/responses/compact",
	}
	for _, path := range paths {
		if !isAIAPIPath(path) {
			t.Fatalf("expected %s to be treated as AI API path", path)
		}
	}
	if isAIAPIPath("/backend-api/codex-status") {
		t.Fatalf("expected /backend-api/codex-status not to be treated as AI API path")
	}
}

func TestGinLogrusLoggerAddsRequestIDForCodexBackend(t *testing.T) {
	gin.SetMode(gin.TestMode)

	engine := gin.New()
	engine.Use(GinLogrusLogger())

	var requestIDFromContext string
	var requestIDFromGin string
	engine.POST("/backend-api/codex/responses", func(c *gin.Context) {
		requestIDFromContext = GetRequestID(c.Request.Context())
		requestIDFromGin = GetGinRequestID(c)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}
	if requestIDFromContext == "" {
		t.Fatalf("expected request ID in request context")
	}
	if requestIDFromGin != requestIDFromContext {
		t.Fatalf("expected Gin request ID %q to match context request ID %q", requestIDFromGin, requestIDFromContext)
	}
}

func TestGinLogrusLoggerMasksManagementAPIKeyDeletionQuery(t *testing.T) {
	previousMode := gin.Mode()
	gin.SetMode(gin.TestMode)
	logger := log.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
	previousLevel := logger.GetLevel()
	hook := logtest.NewLocal(logger)
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() {
		logger.ReplaceHooks(previousHooks)
		logger.SetLevel(previousLevel)
		gin.SetMode(previousMode)
	})

	const fakeKey = "fake-api-key-DO-NOT-USE-0123456789"
	const escapedKey = "%66ake-api-key-DO-NOT-USE-012345678%39"
	const normalQuery = "note=keep%20visible&value_hint=ordinary-value"
	const path = "/v0/management/api-keys"
	for _, tc := range []struct {
		name, param, query, wantQuery string
	}{
		{"value", "value", "value=" + fakeKey, "value=fake...6789"},
		{"escaped_value", "value", "value=" + escapedKey, "value=fake...6789"},
		{"escaped_name_and_value", "value", "v%61lue=" + escapedKey, "v%61lue=fake...6789"},
		{"existing_key", "key", "key=" + fakeKey, "key=fake...6789"},
		{"nonsecret_only", "", normalQuery, normalQuery},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, wantQuery := tc.query, tc.wantQuery
			if tc.param != "" {
				query += "&" + normalQuery
				wantQuery += "&" + normalQuery
			}
			engine := gin.New()
			engine.Use(GinLogrusLogger())
			engine.DELETE(path, func(c *gin.Context) {
				if tc.param != "" && c.Query(tc.param) != fakeKey {
					t.Errorf("handler did not receive the decoded fake key")
				}
				if c.Query("note") != "keep visible" {
					t.Errorf("handler did not receive the decoded nonsecret query")
				}
				c.Status(http.StatusOK)
			})
			hook.Reset()
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, path+"?"+query, nil))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", recorder.Code)
			}
			entries := hook.AllEntries()
			if len(entries) != 1 {
				t.Fatalf("access log count = %d, want 1", len(entries))
			}
			message := entries[0].Message
			if strings.Contains(message, fakeKey) || strings.Contains(message, escapedKey) {
				t.Errorf("access log leaked a full fake key: %q", message)
			}
			if !strings.Contains(message, "DELETE") || !strings.Contains(message, `"`+path+"?"+wantQuery+`"`) {
				t.Errorf("access log = %q, want DELETE and query %q", message, wantQuery)
			}
		})
	}
}

func TestGinLogrusLoggerHealthProbeStatus(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := log.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
	previousLevel := logger.GetLevel()
	hook := logtest.NewLocal(logger)
	logger.SetLevel(log.InfoLevel)
	t.Cleanup(func() { logger.ReplaceHooks(previousHooks); logger.SetLevel(previousLevel) })
	for _, tc := range []struct {
		name, method, path string
		status             int
		wantLog            bool
	}{
		{"get_ok", "GET", "/healthz", 200, false},
		{"head_ok", "HEAD", "/healthz", 200, false},
		{"success_boundary", "GET", "/healthz", 299, false},
		{"redirect", "GET", "/healthz", 300, true},
		{"client_error", "GET", "/healthz", 400, true},
		{"server_error", "HEAD", "/healthz", 503, true},
		{"similar_path", "GET", "/healthz-extra", 200, true},
		{"other_method", "POST", "/healthz", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := gin.New()
			engine.Use(GinLogrusLogger())
			// Simulate an early global middleware response before route handlers run.
			engine.Use(func(c *gin.Context) { c.AbortWithStatus(tc.status) })
			engine.Handle(tc.method, tc.path, func(c *gin.Context) { t.Error("aborted request reached route handler") })
			hook.Reset()
			recorder := httptest.NewRecorder()
			engine.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
			if recorder.Code != tc.status {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.status)
			}
			if got := len(hook.AllEntries()) > 0; got != tc.wantLog {
				t.Errorf("access log present = %v, want %v", got, tc.wantLog)
			}
		})
	}
}
