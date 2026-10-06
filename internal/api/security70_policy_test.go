package api

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestSecurity70V8PolicyFrontendDenial(t *testing.T) {
	for _, location := range []string{"nested", "legacy"} {
		for _, reload := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reload=%v", location, reload), func(t *testing.T) {
				key := "security70-client"
				keys := "api-keys: [" + key + "]\nws-auth: true\n"
				policies := "api-key-policies:\n  - key-sha256: " + config.APIKeyDigest(key) + "\n    allowed-auths: [credential-A]\n    allowed-models: [allowed-model]\n"
				if location == "nested" {
					keys = "access:\n  api-keys: [" + key + "]\n"
					policies = "  api-key-policies:\n    - key-sha256: " + config.APIKeyDigest(key) + "\n      allowed-auths: [credential-A]\n      allowed-models: [allowed-model]\nws-auth: true\n"
				}
				cfg, err := config.ParseConfigBytes([]byte(keys + policies))
				if err != nil {
					t.Fatal(err)
				}
				var s *Server
				if reload {
					old, err := config.ParseConfigBytes([]byte("api-keys: [old-client]\nws-auth: true\n"))
					if err != nil {
						t.Fatal(err)
					}
					s = newTestServerWithConfig(t, old)
					if !s.UpdateClientsContext(context.Background(), cfg) {
						t.Fatal("new-key reload rejected")
					}
				} else {
					s = newTestServerWithConfig(t, cfg)
				}
				capture := &codexSearchCaptureExecutor{}
				s.handlers.AuthManager.RegisterExecutor(capture)
				credential := &auth.Auth{ID: "credential-B", Provider: "codex", Status: auth.StatusActive}
				if _, errRegister := s.handlers.AuthManager.Register(context.Background(), credential); errRegister != nil {
					t.Fatal(errRegister)
				}
				registry.GetGlobalRegistry().RegisterClient(credential.ID, credential.Provider, []*registry.ModelInfo{{ID: "allowed-model"}})
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(credential.ID) })
				authReq := httptest.NewRequest("GET", "/v1/responses", nil)
				authReq.Header.Set("Authorization", "Bearer "+key)
				result, errAuth := s.accessManager.Authenticate(context.Background(), authReq)

				for _, tc := range []struct {
					path, body string
					status     int
					code       string
				}{
					{"/v1/responses", `{"model":"forbidden-model","input":"hi"}`, 403, "api_key_model_forbidden"},
					{"/v1/chat/completions", `{"model":"allowed-model"}`, 503, "api_key_policy_unavailable"},
					{"/v1/responses", `{"model":"allowed-model","input":"hi"}`, 503, "api_key_policy_unavailable"},
				} {
					req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
					req.Header.Set("Authorization", "Bearer "+key)
					rr := httptest.NewRecorder()
					s.engine.ServeHTTP(rr, req)
					if rr.Code != tc.status || !strings.Contains(rr.Body.String(), tc.code) {
						t.Fatalf("restriction not enforced: status=%d body=%s", rr.Code, rr.Body.String())
					}
				}
				if errAuth != nil || result == nil || result.Metadata["key_policy"] == "" {
					t.Fatalf("frontend policy absent: result=%+v err=%v", result, errAuth)
				}
				if len(capture.authIDs) != 0 {
					t.Fatal("disallowed credential dispatched")
				}
			})
		}
	}
}
