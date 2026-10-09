package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/tidwall/gjson"
)

const compactionNoRetryResponsesModel = "compaction-noretry-responses-model"

// An unknown signed compaction block is a deterministic local 409. OpenAI SDK
// clients retry every 409 unless the response carries x-should-retry: false.
func TestResponsesCompactionAffinityMissingSetsShouldRetryFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	executor := &prematureResponsesStreamExecutor{}
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

	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "non-streaming", true: "streaming-before-first-byte"}[stream]
		t.Run(name, func(t *testing.T) {
			streamField := "false"
			if stream {
				streamField = "true"
			}
			body := `{"model":"` + compactionNoRetryResponsesModel + `","stream":` + streamField + `,"input":[{"type":"compaction","encrypted_content":"never-recorded-signer"},{"role":"user","content":"continue"}]}`
			request := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "compaction_affinity_missing") {
				t.Fatalf("body lacks compaction_affinity_missing: %s", recorder.Body.String())
			}
			if code := gjson.Get(recorder.Body.String(), "error.code").String(); code != "" && code != "compaction_affinity_missing" {
				t.Fatalf("error.code = %q; body=%s", code, recorder.Body.String())
			}
			if got := recorder.Header().Get("X-Should-Retry"); got != "false" {
				t.Fatalf("x-should-retry = %q, want false; headers=%v", got, recorder.Header())
			}
		})
	}
}
