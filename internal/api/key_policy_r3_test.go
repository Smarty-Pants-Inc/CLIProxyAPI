package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"gopkg.in/yaml.v3"
)

func r3APIPolicy(key string) config.APIKeyPolicy {
	b := sha256.Sum256([]byte(key))
	return config.APIKeyPolicy{KeySHA256: hex.EncodeToString(b[:]), AllowedAuths: []string{"A"}}
}

func TestR3RestrictedRawEntryMatrix(t *testing.T) {
	key := t.Name()
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}, APIKeyPolicies: []config.APIKeyPolicy{r3APIPolicy(key)}}, WebsocketAuth: true}
	s := newTestServerWithConfig(t, cfg)
	var relayCalls atomic.Int32
	s.AttachWebsocketRoute("/wsrelay", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { relayCalls.Add(1) }))
	for _, route := range []string{
		"GET /v1/responses", "GET /backend-api/codex/responses", "GET /v1/realtime", "GET /v1/realtime?call_id=call", "POST /v1/realtime", "POST /v1/realtime/calls", "GET /v1/realtime/calls/call", "POST /v1/live", "GET /v1/live/call", "POST /v1/realtime/client_secrets", "POST /v1/realtime/sessions", "POST /v1/realtime/transcription_sessions", "GET /v1/realtime/translations", "POST /v1/realtime/translations", "POST /v1/realtime/translations/client_secrets", "POST /v1/realtime/calls/call/hangup", "POST /v1/realtime/calls/call/accept", "POST /v1/realtime/calls/call/reject", "POST /v1/realtime/calls/call/refer", "GET /wsrelay",
	} {
		t.Run(route, func(t *testing.T) {
			parts := strings.SplitN(route, " ", 2)
			req := httptest.NewRequest(parts[0], parts[1], strings.NewReader(`{"model":"gpt-live-1-codex"}`))
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
			rr := httptest.NewRecorder()
			s.engine.ServeHTTP(rr, req)
			if rr.Code != 503 || !strings.Contains(rr.Body.String(), "api_key_policy_unavailable") {
				t.Fatalf("entry not refused safely: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
	if relayCalls.Load() != 0 {
		t.Fatal("wsrelay resource handler invoked")
	}
}

func TestR3ServerReloadFreezesPolicyPublication(t *testing.T) {
	for _, change := range []string{"added", "removed", "changed"} {
		t.Run(change, func(t *testing.T) {
			key := t.Name()
			old := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{key}}, WebsocketAuth: true}
			if change != "added" {
				old.APIKeyPolicies = []config.APIKeyPolicy{r3APIPolicy(key)}
			}
			s := newTestServerWithConfig(t, old)
			next := old.CloneForRuntime()
			next.RequestLog = !old.RequestLog
			switch change {
			case "added":
				next.APIKeyPolicies = []config.APIKeyPolicy{r3APIPolicy(key)}
			case "removed":
				next.APIKeyPolicies = nil
			case "changed":
				next.APIKeyPolicies[0].AllowedAuths = []string{"B"}
			}
			if !s.UpdateClientsContext(context.Background(), next) {
				t.Fatal("reload rejected")
			}
			if !reflect.DeepEqual(s.cfg.APIKeyPolicies, old.APIKeyPolicies) {
				t.Fatal("server config published policy change")
			}
			var published config.Config
			if err := yaml.Unmarshal(s.oldConfigYaml, &published); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(published.APIKeyPolicies, old.APIKeyPolicies) {
				t.Fatal("server YAML snapshot published policy change")
			}
			if s.cfg.RequestLog == old.RequestLog {
				t.Fatal("unrelated reload lost")
			}
			req := httptest.NewRequest("GET", "/v1/realtime", nil)
			req.Header.Set("Authorization", "Bearer "+key)
			result, errAuth := s.accessManager.Authenticate(context.Background(), req)
			if errAuth != nil || result == nil {
				t.Fatalf("auth failed: %v", errAuth)
			}
			if (result.Metadata["key_policy"] != "") != (change != "added") {
				t.Fatal("access provider published hot policy change")
			}
			// A new process adopts the requested policy, including additions to old keys.
			restarted := newTestServerWithConfig(t, next)
			if !reflect.DeepEqual(restarted.handlers.AuthManager.KeyPolicies(key), next.APIKeyPolicies) {
				t.Fatal("restart ignored policy")
			}
			if change != "removed" {
				rr := httptest.NewRecorder()
				restarted.engine.ServeHTTP(rr, req)
				if rr.Code != 503 {
					t.Fatalf("restart realtime not refused: %d", rr.Code)
				}
			}
		})
	}
}
