package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers/openai"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Intercept only policied clients. A private built-in handler has no plugin host,
// including if configuration changes while this admitted request is running.
func admitKeyPolicy(c *gin.Context, managers []*auth.Manager) (func(), bool) {
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
