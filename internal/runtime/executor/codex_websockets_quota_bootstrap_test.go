package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const codexBootstrapQuotaError = `{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":3600}`

func TestCodexWebsocketsExecutor_QuotaBootstrapPreservesCooling(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, modelLevelCooling := range []bool{true, false} {
		for _, eventType := range []string{"response.failed", "error"} {
			for _, quota := range []struct {
				name       string
				body       string
				retryAfter time.Duration
			}{
				{name: "usage_limit_reached", body: codexBootstrapQuotaError, retryAfter: time.Hour},
				{name: "insufficient_quota", body: `{"code":"insufficient_quota","message":"You exceeded your current quota"}`},
			} {
				t.Run(fmt.Sprintf("model_cooling=%t/%s/%s", modelLevelCooling, eventType, quota.name), func(t *testing.T) {
					event := fmt.Sprintf(`{"type":"response.failed","response":{"id":"resp_1","status":"failed","error":%s}}`, quota.body)
					if eventType == "error" {
						// No status field: this must exercise terminal conversion and bootstrap
						// failover, not the separate explicit-status websocket error path.
						event = fmt.Sprintf(`{"type":"error","error":%s}`, quota.body)
					}
					server := codexWebsocketServer(t, codexCreatedEvent, codexInProgressEvent, event)
					defer server.Close()

					cfg := &config.Config{Codex: config.CodexConfig{ModelLevelCooling: modelLevelCooling}}
					req, opts := codexWebsocketRequest()
					result, err := NewCodexWebsocketsExecutor(cfg).ExecuteStream(context.Background(), codexTestAuth(server.URL), req, opts)
					if result != nil || err == nil {
						t.Fatalf("ExecuteStream = %v, %v; want synchronous quota failure without a leaked handshake", result, err)
					}
					assertCodexBootstrapQuotaContract(t, err, !modelLevelCooling, quota.retryAfter)
				})
			}
		}
	}
}

func assertCodexBootstrapQuotaContract(t *testing.T, err error, credentialScoped bool, retryAfter time.Duration) {
	t.Helper()
	if got := statusCodeFromTestError(t, err); got != http.StatusTooManyRequests {
		t.Errorf("status code = %d, want 429", got)
	}
	var scoped interface{ IsCredentialScoped() bool }
	if !errors.As(err, &scoped) {
		t.Errorf("quota error %T lost its cooling scope", err)
	} else if got := scoped.IsCredentialScoped(); got != credentialScoped {
		t.Errorf("credential scope = %t, want %t", got, credentialScoped)
	}
	var retry interface{ RetryAfter() *time.Duration }
	if !errors.As(err, &retry) {
		t.Errorf("quota error %T lost its reset interface", err)
		return
	}
	got := retry.RetryAfter()
	if retryAfter == 0 {
		if got != nil {
			t.Errorf("RetryAfter = %v, want nil for quota without reset", *got)
		}
	} else if got == nil || *got != retryAfter {
		t.Errorf("RetryAfter = %v, want %v", got, retryAfter)
	}
}

type codexBootstrapQuotaResultHook struct {
	cliproxyauth.NoopHook
	results chan cliproxyauth.Result
}

func (h *codexBootstrapQuotaResultHook) OnResult(_ context.Context, result cliproxyauth.Result) {
	h.results <- result
}

func TestCodexWebsocketsExecutor_QuotaBootstrapSiblingAvailability(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, modelLevelCooling := range []bool{true, false} {
		t.Run(fmt.Sprintf("model_cooling=%t", modelLevelCooling), func(t *testing.T) {
			model := fmt.Sprintf("quota-bootstrap-exhausted-%t", modelLevelCooling)
			siblingModel := fmt.Sprintf("quota-bootstrap-sibling-%t", modelLevelCooling)
			var quotaAttempts, siblingAttempts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if errUpgrade != nil {
					t.Errorf("upgrade websocket: %v", errUpgrade)
					return
				}
				defer func() { _ = conn.Close() }()
				_, payload, errRead := conn.ReadMessage()
				if errRead != nil {
					t.Errorf("read websocket request: %v", errRead)
					return
				}
				requestedModel := gjson.GetBytes(payload, "model").String()
				var terminal string
				switch requestedModel {
				case model:
					quotaAttempts.Add(1)
					terminal = fmt.Sprintf(`{"type":"response.failed","response":{"id":"resp_quota","model":%q,"status":"failed","error":%s}}`, model, codexBootstrapQuotaError)
				case siblingModel:
					siblingAttempts.Add(1)
					terminal = fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp_sibling","model":%q,"status":"completed","output":[]}}`, siblingModel)
				default:
					t.Errorf("unexpected upstream model: %q", requestedModel)
					return
				}
				created := fmt.Sprintf(`{"type":"response.created","response":{"id":"resp_bootstrap","model":%q,"output":[]}}`, requestedModel)
				for _, frame := range []string{created, terminal} {
					if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
						t.Errorf("write websocket response: %v", errWrite)
						return
					}
				}
			}))
			defer server.Close()

			cfg := &config.Config{Codex: config.CodexConfig{ModelLevelCooling: modelLevelCooling}}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
			hook := &codexBootstrapQuotaResultHook{results: make(chan cliproxyauth.Result, 8)}
			manager := cliproxyauth.NewManager(nil, &cliproxyauth.FillFirstSelector{}, hook)
			manager.SetConfig(cfg)
			manager.SetRetryConfig(0, 0, 0)
			manager.RegisterExecutor(exec)
			candidate := &cliproxyauth.Auth{
				ID: t.Name(), Provider: "codex", Status: cliproxyauth.StatusActive,
				Attributes: map[string]string{"api_key": "fixture-only", "base_url": server.URL, "websockets": "true"},
				// Explicitly enable cooling without mutating the process-wide test setting.
				Metadata: map[string]any{"disable_cooling": false},
			}
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(candidate.ID, "codex", []*registry.ModelInfo{{ID: model}, {ID: siblingModel}})
			t.Cleanup(func() { reg.UnregisterClient(candidate.ID) })
			ctx := context.Background()
			if _, errRegister := manager.Register(ctx, candidate); errRegister != nil {
				t.Fatal(errRegister)
			}
			execute := func(requestedModel string) (*cliproxyexecutor.StreamResult, error) {
				return manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{
					Model: requestedModel, Payload: []byte(fmt.Sprintf(`{"model":%q,"input":[]}`, requestedModel)),
				}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex"), Stream: true})
			}

			before := time.Now()
			result, err := execute(model)
			if result != nil || err == nil {
				t.Fatalf("manager ExecuteStream = %v, %v; want synchronous quota failure", result, err)
			}
			assertCodexBootstrapQuotaContract(t, err, !modelLevelCooling, time.Hour)
			select {
			case recorded := <-hook.results:
				if recorded.AuthID != candidate.ID || recorded.Model != model || recorded.Success || recorded.Error == nil || recorded.Error.HTTPStatus != 429 {
					t.Errorf("quota result lost auth/model/status attribution: %+v", recorded)
				}
				if recorded.CredentialScope != !modelLevelCooling || recorded.RetryAfter == nil || *recorded.RetryAfter != time.Hour {
					t.Errorf("quota result lost scope or reset: %+v", recorded)
				}
			default:
				t.Fatal("manager did not record the quota failure")
			}
			cooled, ok := manager.GetByID(candidate.ID)
			if !ok {
				t.Fatal("manager lost the fixture credential")
			}
			state := cooled.ModelStates[model]
			if state == nil || !state.Unavailable || !state.Quota.Exceeded || state.NextRetryAfter.Before(before.Add(time.Hour)) {
				t.Errorf("exhausted model lost its one-hour cooldown: %+v", state)
			}
			if !modelLevelCooling && (cooled.Quota.Reason != "credential_quota" || cooled.Quota.NextRecoverAt.Before(before.Add(time.Hour))) {
				t.Errorf("disabled model cooling must retain credential-wide quota: %+v", cooled.Quota)
			}

			// Probe scheduler selection through actual requests, not just the error marker
			// or a synthetic MarkResult: the exhausted model stays blocked in both modes.
			if blockedResult, errBlocked := execute(model); errBlocked == nil || blockedResult != nil {
				t.Errorf("exhausted model was selectable before reset: %v, %v", blockedResult, errBlocked)
			}
			result, err = execute(siblingModel)
			if modelLevelCooling {
				if err != nil || result == nil {
					t.Errorf("sibling model must remain available on the same credential: %v", err)
				} else {
					completed := false
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Errorf("sibling stream failed: %v", chunk.Err)
						}
						if gjson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
							completed = true
						}
					}
					if !completed {
						t.Error("available sibling did not complete its real websocket request")
					}
				}
			} else if err == nil || result != nil {
				t.Errorf("credential-wide quota must block the sibling model: %v, %v", result, err)
			}
			wantSiblingAttempts := int32(0)
			if modelLevelCooling {
				wantSiblingAttempts = 1
			}
			if quotaAttempts.Load() != 1 || siblingAttempts.Load() != wantSiblingAttempts {
				t.Errorf("upstream attempts: exhausted=%d (want 1), sibling=%d (want %d)", quotaAttempts.Load(), siblingAttempts.Load(), wantSiblingAttempts)
			}
		})
	}
}
