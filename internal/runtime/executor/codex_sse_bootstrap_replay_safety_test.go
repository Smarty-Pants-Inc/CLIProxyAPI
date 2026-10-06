package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const (
	codexSSEReplayModel    = "gpt-5.6-terra"
	codexSSEReplayPreamble = `{"type":"response.created","response":{"id":"resp_sse_replay","output":[]}}`
	codexSSEReplayTool     = `{"type":"response.output_item.added","output_index":0,"item":{"id":"search_sse_replay","type":"web_search_call","status":"in_progress"}}`
	codexSSEReplayIdentity = `{"type":"response.in_progress","response":{"id":"resp_sse_replay","model":"gpt-5.6-terra"}}`
)

var codexSSEReplayQuotas = []struct {
	name       string
	body       string
	retryAfter time.Duration
}{
	{name: "usage_limit_reached", body: `{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":3600}`, retryAfter: time.Hour},
	{name: "insufficient_quota_type", body: `{"type":"insufficient_quota","message":"You exceeded your current quota"}`},
	{name: "insufficient_quota_code", body: `{"code":"insufficient_quota","message":"You exceeded your current quota"}`},
}

func codexSSEReplayQuotaEvent(body string) string {
	return fmt.Sprintf(`{"type":"response.failed","response":{"id":"resp_sse_replay","status":"failed","error":%s}}`, body)
}

// Both credentials are loopback-only fixtures. The second succeeds so an accidental
// conductor retry is observable as both an extra request and a replaced response.
func codexSSEReplayManager(t *testing.T, events []string, modelLevelCooling bool, truncateBody ...bool) (*cliproxyauth.Manager, *atomic.Int32, *atomic.Int32, string) {
	t.Helper()
	first := codexSSEServer(events...)
	t.Cleanup(first.Close)
	second := codexSSEServer(codexCreatedEvent, codexCompletedEventBody)
	t.Cleanup(second.Close)
	var firstAttempts, secondAttempts atomic.Int32
	firstHandler, secondHandler := first.Config.Handler, second.Config.Handler
	first.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstAttempts.Add(1)
		if len(truncateBody) > 0 && truncateBody[0] {
			// Closing a shorter body produces an actual transport read error
			// after the small preamble and unsafe event have been consumed.
			w.Header().Set("Content-Length", "1048576")
		}
		firstHandler.ServeHTTP(w, r)
	})
	second.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondAttempts.Add(1)
		secondHandler.ServeHTTP(w, r)
	})
	// These fixtures exercise opt-in bootstrap retry and replay safety.
	cfg := &config.Config{Codex: config.CodexConfig{ModelLevelCooling: modelLevelCooling, StreamBootstrapBuffering: true}}
	manager := cliproxyauth.NewManager(nil, &cliproxyauth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(NewCodexExecutor(cfg))
	firstID := "a-sse-replay-" + t.Name()
	for i, endpoint := range []string{first.URL, second.URL} {
		id := firstID
		if i == 1 {
			id = "b-sse-replay-" + t.Name()
		}
		candidate := &cliproxyauth.Auth{
			ID: id, Provider: "codex", Status: cliproxyauth.StatusActive,
			Attributes: map[string]string{"api_key": "sse-fixture-only", "base_url": endpoint},
			Metadata:   map[string]any{"disable_cooling": false},
		}
		reg := registry.GetGlobalRegistry()
		reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: "gpt-5.6-terra"}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
		if _, errRegister := manager.Register(context.Background(), candidate); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	return manager, &firstAttempts, &secondAttempts, firstID
}

func codexSSEReplayExecute(t *testing.T, manager *cliproxyauth.Manager) (*cliproxyexecutor.StreamResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	req, opts := codexTestRequest()
	// Native Responses events make preservation of the held server-tool frame
	// directly observable, rather than depending on a lossy chat translator.
	opts.SourceFormat = sdktranslator.FromString("codex")
	return manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
}

func codexSSEReplayAssertQuota(t *testing.T, err error, credentialScoped bool, retryAfter time.Duration) {
	t.Helper()
	if err == nil {
		t.Fatal("quota error was lost")
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) || status.StatusCode() != http.StatusTooManyRequests {
		t.Errorf("quota status lost: %T %v; want 429", err, err)
	}
	var scoped interface{ IsCredentialScoped() bool }
	if !errors.As(err, &scoped) || scoped.IsCredentialScoped() != credentialScoped {
		t.Errorf("quota error lost cooling scope (want credential-scoped=%t): %T %v", credentialScoped, err, err)
	}
	var retry interface{ RetryAfter() *time.Duration }
	if !errors.As(err, &retry) {
		t.Fatalf("quota error lost reset interface: %T", err)
	}
	got := retry.RetryAfter()
	if retryAfter == 0 {
		if got != nil {
			t.Errorf("RetryAfter = %v, want nil", *got)
		}
	} else if got == nil || *got != retryAfter {
		t.Errorf("RetryAfter = %v, want %v", got, retryAfter)
	}
	var requestScoped interface{ IsRequestScoped() bool }
	if errors.As(err, &requestScoped) && requestScoped.IsRequestScoped() {
		t.Errorf("verified in-stream quota must not become request-scoped: %v", err)
	}
}

func TestCodexSSEBootstrapReplaySafety_LateIdentityToolQuotaDoesNotRetry(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, modelLevelCooling := range []bool{true, false} {
		for _, quota := range codexSSEReplayQuotas {
			t.Run(fmt.Sprintf("model_cooling=%t/%s", modelLevelCooling, quota.name), func(t *testing.T) {
				manager, firstAttempts, secondAttempts, _ := codexSSEReplayManager(t, []string{
					codexSSEReplayPreamble, codexSSEReplayTool, codexSSEReplayIdentity, codexSSEReplayQuotaEvent(quota.body),
				}, modelLevelCooling)
				result, err := codexSSEReplayExecute(t, manager)
				if result == nil || err != nil {
					t.Fatalf("verified tool stream must be returned, not synchronously failed: result=%v err=%v", result, err)
				}
				payload, streamErr := drainChunks(result)
				if firstAttempts.Load() != 1 || secondAttempts.Load() != 0 {
					t.Errorf("unsafe bootstrap replayed: first=%d second=%d; want 1,0", firstAttempts.Load(), secondAttempts.Load())
				}
				for _, held := range []string{codexSSEReplayPreamble, codexSSEReplayTool, codexSSEReplayIdentity} {
					if !strings.Contains(payload, held) {
						t.Errorf("held event lost after identity verification: %s; payload=%s", held, payload)
					}
				}
				if strings.Index(payload, codexSSEReplayTool) > strings.Index(payload, codexSSEReplayIdentity) {
					t.Error("held tool and identity events were reordered")
				}
				codexSSEReplayAssertQuota(t, streamErr, !modelLevelCooling, quota.retryAfter)
			})
		}
	}
}

func TestCodexSSEBootstrapReplaySafety_SafeLateIdentityQuotaStillRetries(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, quota := range codexSSEReplayQuotas {
		t.Run(quota.name, func(t *testing.T) {
			manager, firstAttempts, secondAttempts, _ := codexSSEReplayManager(t, []string{
				codexSSEReplayPreamble, codexSSEReplayIdentity, codexSSEReplayQuotaEvent(quota.body),
			}, true)
			result, err := codexSSEReplayExecute(t, manager)
			if result == nil || err != nil {
				t.Fatalf("safe bootstrap must allow second credential success: result=%v err=%v", result, err)
			}
			payload, streamErr := drainChunks(result)
			if firstAttempts.Load() != 1 || secondAttempts.Load() != 1 {
				t.Errorf("safe bootstrap attempts = %d,%d; want 1,1", firstAttempts.Load(), secondAttempts.Load())
			}
			if streamErr != nil || !strings.Contains(payload, `"type":"response.completed"`) || strings.Contains(payload, "resp_sse_replay") {
				t.Errorf("safe retry must replace first handshake with second success: payload=%s err=%v", payload, streamErr)
			}
		})
	}
}

func TestCodexSSEBootstrapReplaySafety_ConfiguredContinueCannotReplayUnsafeTool(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, unsafe := range []bool{true, false} {
		t.Run(fmt.Sprintf("unsafe=%t", unsafe), func(t *testing.T) {
			events := []string{codexSSEReplayPreamble}
			if unsafe {
				events = append(events, codexSSEReplayTool)
			}
			events = append(events, `{"type":"response.in_progress","response":{"model":"wrong-model"}}`)
			manager, firstAttempts, secondAttempts, firstID := codexSSEReplayManager(t, events, true)
			candidate, ok := manager.GetByID(firstID)
			if !ok {
				t.Fatal("primary fixture credential disappeared")
			}
			candidate.Metadata["request_scoped_errors"] = []config.RequestScopedErrorRule{{
				Status: http.StatusBadGateway,
				Match:  []string{`upstream response.model "wrong-model" does not match`},
				Action: cliproxyauth.RequestScopedActionContinue,
			}}
			if _, errUpdate := manager.Update(context.Background(), candidate); errUpdate != nil {
				t.Fatal(errUpdate)
			}
			result, err := codexSSEReplayExecute(t, manager)
			if firstAttempts.Load() != 1 {
				t.Errorf("primary attempts = %d, want 1", firstAttempts.Load())
			}
			if !unsafe {
				// This control proves the identical 502/body rule is active and
				// may continue to the second credential for a replay-safe attempt.
				if result == nil || err != nil {
					t.Fatalf("safe configured continue failed: result=%v err=%v", result, err)
				}
				payload, streamErr := drainChunks(result)
				if secondAttempts.Load() != 1 || streamErr != nil || !strings.Contains(payload, `"type":"response.completed"`) {
					t.Errorf("safe continue did not complete through second credential: second=%d payload=%s err=%v", secondAttempts.Load(), payload, streamErr)
				}
				return
			}
			if result != nil {
				payload, streamErr := drainChunks(result)
				t.Errorf("configured continue released a replacement stream: payload=%s err=%v", payload, streamErr)
			}
			if secondAttempts.Load() != 0 {
				t.Errorf("configured continue replayed unsafe tool: second=%d, want 0", secondAttempts.Load())
			}
			if err == nil {
				t.Fatal("unsafe configured continue must terminate synchronously")
			}
			var stop interface{ IsRequestStop() bool }
			if !errors.As(err, &stop) || !stop.IsRequestStop() {
				t.Errorf("unsafe error lost hard-stop marker: %T %v", err, err)
			}
			var mismatch *helps.CodexModelMismatchError
			if !errors.As(err, &mismatch) || mismatch.StatusCode() != http.StatusBadGateway {
				t.Errorf("hard-stop wrapper lost original 502/model mismatch: %T %v", err, err)
			}
		})
	}
}

func TestCodexSSEBootstrapReplaySafety_UnverifiedToolErrorsDoNotRetryOrLeak(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	cases := []struct {
		name          string
		tail          []string
		modelMismatch bool
		readError     bool
		upstreamQuota bool
	}{
		{name: "wrong_identity", tail: []string{`{"type":"response.in_progress","response":{"model":"wrong-model"}}`}, modelMismatch: true},
		{name: "missing_terminal_identity", tail: []string{`{"type":"response.completed","response":{"output":[]}}`}, modelMismatch: true},
		{name: "missing_identity_eof"},
		{name: "missing_identity_usage_quota", tail: []string{codexSSEReplayQuotaEvent(codexSSEReplayQuotas[0].body)}, upstreamQuota: true},
		{name: "missing_identity_quota_type", tail: []string{codexSSEReplayQuotaEvent(codexSSEReplayQuotas[1].body)}, upstreamQuota: true},
		{name: "missing_identity_quota_code", tail: []string{codexSSEReplayQuotaEvent(codexSSEReplayQuotas[2].body)}, upstreamQuota: true},
		// Explicit error.status is not a separate SSE HTTP-status path. It must
		// not reopen retries once the preceding server-tool frame made replay unsafe.
		{name: "explicit_error_status", tail: []string{`{"type":"error","status":429,"error":{"type":"usage_limit_reached","message":"quota"}}`}, upstreamQuota: true},
		{name: "body_read_error", readError: true},
		{name: "unverified_frame_budget", tail: make([]string, codexBootstrapMaxBufferedFrames)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := append([]string{codexSSEReplayPreamble, codexSSEReplayTool}, tc.tail...)
			manager, firstAttempts, secondAttempts, _ := codexSSEReplayManager(t, events, true, tc.readError)
			result, err := codexSSEReplayExecute(t, manager)
			if result != nil {
				payload, streamErr := drainChunks(result)
				t.Errorf("unverified stream escaped: payload=%s streamErr=%v", payload, streamErr)
			}
			if firstAttempts.Load() != 1 || secondAttempts.Load() != 0 {
				t.Errorf("unverified unsafe bootstrap replayed: first=%d second=%d; want 1,0", firstAttempts.Load(), secondAttempts.Load())
			}
			if err == nil {
				t.Fatal("unverified unsafe attempt must terminate with a synchronous error")
			}
			var stop interface{ IsRequestStop() bool }
			if !errors.As(err, &stop) || !stop.IsRequestStop() {
				t.Errorf("unsafe synchronous error must prevent credential retries: %T %v", err, err)
			}
			// Upstream quota refusals keep their own cooling scope (see
			// UnverifiedToolQuotaKeepsCooldown); local failures stay request-scoped.
			var requestScoped interface{ IsRequestScoped() bool }
			if gotScoped := errors.As(err, &requestScoped) && requestScoped.IsRequestScoped(); gotScoped == tc.upstreamQuota {
				t.Errorf("request-scoped = %t, want %t: %T %v", gotScoped, !tc.upstreamQuota, err, err)
			}
			if tc.readError && !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("non-replayable wrapper must preserve read error via Unwrap: %T %v", err, err)
			}
			if tc.modelMismatch {
				var mismatch *helps.CodexModelMismatchError
				if !errors.As(err, &mismatch) {
					t.Errorf("non-replayable wrapper must preserve model mismatch via Unwrap: %T %v", err, err)
				}
			}
		})
	}
}

// An unverified unsafe quota refusal must stop this turn without dropping the
// scheduler's quota state, so the next independent request picks a healthy credential.
func TestCodexSSEBootstrapReplaySafety_UnverifiedToolQuotaKeepsCooldown(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, modelLevelCooling := range []bool{true, false} {
		for _, quota := range codexSSEReplayQuotas {
			t.Run(fmt.Sprintf("model_cooling=%t/%s", modelLevelCooling, quota.name), func(t *testing.T) {
				manager, firstAttempts, secondAttempts, firstID := codexSSEReplayManager(t, []string{
					codexSSEReplayPreamble, codexSSEReplayTool, codexSSEReplayQuotaEvent(quota.body),
				}, modelLevelCooling)
				result, err := codexSSEReplayExecute(t, manager)
				if result != nil {
					payload, streamErr := drainChunks(result)
					t.Fatalf("unverified stream escaped: payload=%s streamErr=%v", payload, streamErr)
				}
				if firstAttempts.Load() != 1 || secondAttempts.Load() != 0 {
					t.Fatalf("unsafe turn attempts = %d,%d; want 1,0", firstAttempts.Load(), secondAttempts.Load())
				}
				var stop interface{ IsRequestStop() bool }
				if !errors.As(err, &stop) || !stop.IsRequestStop() {
					t.Errorf("unsafe quota lost hard stop: %T %v", err, err)
				}
				codexSSEReplayAssertQuota(t, err, !modelLevelCooling, quota.retryAfter)

				auth, ok := manager.GetByID(firstID)
				if !ok {
					t.Fatal("primary fixture credential disappeared")
				}
				state := auth.ModelStates[codexSSEReplayModel]
				if state == nil || !state.Quota.Exceeded || !state.NextRetryAfter.After(time.Now()) {
					t.Errorf("model quota cooldown not recorded: %+v", state)
				}
				if credentialQuota := auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota"; credentialQuota != !modelLevelCooling {
					t.Errorf("credential quota = %t (%+v); want %t", credentialQuota, auth.Quota, !modelLevelCooling)
				}

				next, errNext := codexSSEReplayExecute(t, manager)
				if errNext != nil || next == nil {
					t.Fatalf("next independent request failed: %v", errNext)
				}
				payload, streamErr := drainChunks(next)
				if firstAttempts.Load() != 1 || secondAttempts.Load() != 1 {
					t.Errorf("next request attempts = %d,%d; want exhausted credential skipped (1,1)", firstAttempts.Load(), secondAttempts.Load())
				}
				if streamErr != nil || !strings.Contains(payload, `"type":"response.completed"`) {
					t.Errorf("next request did not complete on healthy credential: payload=%s err=%v", payload, streamErr)
				}
			})
		}
	}
}
