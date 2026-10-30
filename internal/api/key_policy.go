package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// Intercept only policied clients. A private built-in handler has no plugin host,
// including if configuration changes while this admitted request is running.
func admitKeyPolicy(c *gin.Context, managers []*auth.Manager) (func(), bool) {
	if len(managers) > 0 && managers[0] != nil && managers[0].PoolMode() {
		return admitPoolKeyPolicy(c, managers[0])
	}
	key := c.GetString("userApiKey")
	var policies []config.APIKeyPolicy
	if metadata, ok := c.Get("accessMetadata"); ok {
		if values, ok := metadata.(map[string]string); ok && values["key_policy"] != "" {
			if json.Unmarshal([]byte(values["key_policy"]), &policies) != nil {
				c.AbortWithStatusJSON(503, gin.H{"error": "api_key_policy_unavailable"})
				return func() {}, false
			}
		}
	}
	var m *auth.Manager
	if len(managers) != 0 {
		m = managers[0]
	}
	if m != nil {
		policies = append(policies, m.KeyPolicies(key)...)
	}
	if len(policies) == 0 {
		return func() {}, true
	}
	fail := func(err error) (func(), bool) {
		status := 503
		if typed, ok := err.(interface{ StatusCode() int }); ok {
			status = typed.StatusCode()
		}
		c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"message": err.Error(), "code": err.Error()}})
		return func() {}, false
	}
	unavailable := &auth.Error{HTTPStatus: 503, Message: "api_key_policy_unavailable"}
	path := c.Request.URL.Path
	if m == nil || c.Request.Method != http.MethodPost || (path != "/v1/responses" && path != "/backend-api/codex/responses") {
		return fail(unavailable)
	}
	// F32: bound encoded and decoded bytes before model checks or admission.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<20)
	body, err := handlers.ReadRequestBodyLimit(c, 16<<20)
	if err != nil {
		return fail(&auth.Error{HTTPStatus: 400, Message: "invalid policy request body"})
	}
	model, err := ex.PolicyModel(body)
	if err != nil {
		return fail(&auth.Error{HTTPStatus: 400, Message: err.Error()})
	}
	ctx, done, err := m.BeginKeyPolicy(c.Request.Context(), policies, model)
	if err != nil {
		return fail(err)
	}
	defer done()
	c.Request = c.Request.WithContext(ctx)
	c.Request.Header.Del("Content-Encoding")
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	// Keep protocol/error handling and SSE delivery, but no plugins/bootstrap retries.
	clean := handlers.NewBaseAPIHandlers(&config.SDKConfig{}, m)
	openai.NewOpenAIResponsesAPIHandler(clean).Responses(c)
	c.Abort()
	return func() {}, false
}

// Pool admission keeps the normal protocol handlers and conductor retry paths.
// Live is classified here, but its bounded canonical model parser owns Begin;
// stored-call WSS attaches the original operation and never acquires another slot.
func admitPoolKeyPolicy(c *gin.Context, m *auth.Manager) (func(), bool) {
	noop := func() {}
	fail := func(code string, status int) (func(), bool) {
		c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"message": code, "code": code}})
		return noop, false
	}
	if !coreusage.IsNativeAccessProvider(c.GetString("accessProvider")) || c.GetString("userApiKey") == "" {
		return fail("api_key_pool_unclassified", 403)
	}
	_, class, err := m.PoolPrincipal(c.GetString("userApiKey"))
	if err != nil {
		status := 503
		if typed, ok := err.(interface{ StatusCode() int }); ok {
			status = typed.StatusCode()
		}
		return fail(err.Error(), status)
	}
	path, method := c.Request.URL.Path, c.Request.Method
	if method == http.MethodGet && !websocket.IsWebSocketUpgrade(c.Request) && (path == "/v1/models" || strings.HasPrefix(path, "/v1/models/")) {
		return noop, true
	}
	if path == "/v1/live" && method == http.MethodPost {
		if class != "human" || websocket.IsWebSocketUpgrade(c.Request) {
			return fail("api_key_pool_path_unavailable", 503)
		}
		return noop, true
	}
	if method == http.MethodGet && strings.HasPrefix(path, "/v1/live/") && len(strings.TrimPrefix(path, "/v1/live/")) != 0 && !strings.Contains(strings.TrimPrefix(path, "/v1/live/"), "/") {
		if class != "human" {
			return fail("api_key_pool_path_unavailable", 503)
		}
		// Keep the live handler's native 426 response for a non-WS join.
		return noop, true
	}
	if method != http.MethodPost || websocket.IsWebSocketUpgrade(c.Request) {
		return fail("api_key_pool_path_unavailable", 503)
	}
	var kind auth.PoolOperationKind
	switch path {
	case "/v1/responses", "/backend-api/codex/responses":
		kind = auth.PoolResponses
	case "/v1/responses/compact", "/backend-api/codex/responses/compact":
		kind = auth.PoolCompact
	case "/v1/messages":
		kind = auth.PoolMessages
	case "/v1/messages/count_tokens":
		kind = auth.PoolCountTokens
	default:
		return fail("api_key_pool_path_unavailable", 503)
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 16<<20)
	body, err := handlers.ReadRequestBodyLimit(c, 16<<20)
	if err != nil {
		if errors.Is(err, handlers.ErrRequestBodyTooLarge) {
			return fail("request body too large", 413)
		}
		return fail("invalid pool request body", 400)
	}
	model, err := ex.PolicyModel(body)
	if err != nil {
		return fail("invalid pool request body", 400)
	}
	ctx, op, err := m.BeginPoolOperation(c.Request.Context(), c.GetString("userApiKey"), model, kind)
	if err != nil {
		status := 503
		if typed, ok := err.(interface{ StatusCode() int }); ok {
			status = typed.StatusCode()
		}
		return fail(err.Error(), status)
	}
	c.Request = c.Request.WithContext(ctx)
	c.Request.Header.Del("Content-Encoding")
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	return op.Finish, true
}
