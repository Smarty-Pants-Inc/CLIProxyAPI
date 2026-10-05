package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// Match AntigravityExecutor.executeCompaction's nonstream wire shape (built by
// helps.BuildAntigravityCompactionResponse), not a native Claude content block.
// Capsule encryption is opaque to the conductor; runtime capsule tests cover it.
const creditsCompactionResponse = `{"id":"resp_ag_compact_test","object":"response.compaction","created_at":1,"model":"claude-sonnet-4-6","status":"completed","output":[{"id":"cmp_ag_compact_test","type":"compaction","status":"completed","encrypted_content":"cpa-ag-compact-v1:opaque-test-capsule"}],"usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15}}`

const creditsOrdinaryResponse = `{"object":"response","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"credits answer"}]}]}`

type compactionCreditsCall struct {
	authID  string
	pinned  string
	credits bool
}

type compactionCreditsExecutor struct {
	compactTestExecutor
	calls          []compactionCreditsCall
	normalSucceeds bool
	creditsFailID  string
	output         []byte
	beforeReturn   func()
}

func (*compactionCreditsExecutor) Identifier() string { return "antigravity" }

func (e *compactionCreditsExecutor) Execute(ctx context.Context, auth *Auth, _ cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	cliproxyexecutor.MarkUpstreamAttempt(ctx)
	credits := AntigravityCreditsRequested(ctx)
	e.calls = append(e.calls, compactionCreditsCall{authID: auth.ID, pinned: pinnedAuthIDFromMetadata(opts.Metadata), credits: credits})
	if !credits {
		if e.normalSucceeds {
			return cliproxyexecutor.Response{Payload: []byte(creditsOrdinaryResponse)}, nil
		}
		return cliproxyexecutor.Response{}, compactTestStatusError{code: http.StatusTooManyRequests, msg: "normal quota exhausted"}
	}
	if auth.ID == e.creditsFailID {
		return cliproxyexecutor.Response{}, compactTestStatusError{code: http.StatusServiceUnavailable, msg: "actual signer credits failure"}
	}
	if e.beforeReturn != nil {
		e.beforeReturn()
	}
	return cliproxyexecutor.Response{Payload: e.output, Headers: http.Header{"X-Credits-Test": {"produced"}}}, nil
}

func newCompactionCreditsManager(t *testing.T, selector *SessionAffinitySelector, executor *compactionCreditsExecutor, firstID, secondID string) *Manager {
	t.Helper()
	manager := NewManager(nil, selector, nil)
	cfg := &internalconfig.Config{}
	cfg.QuotaExceeded.AntigravityCredits = true
	cfg.Routing.SessionAffinity = true
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	for _, id := range []string{firstID, secondID} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "antigravity", Status: StatusActive}); errRegister != nil {
			t.Fatalf("Register(%s): %v", id, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(id, "antigravity", []*registry.ModelInfo{{ID: "claude-sonnet-4-6"}})
		t.Cleanup(func() {
			registry.GetGlobalRegistry().UnregisterClient(id)
			antigravityCreditsHintByAuth.Delete(id)
		})
	}
	return manager
}

func compactionCreditsRequest(kind string, output []byte) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	body := `{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]}`
	if kind == "trigger" {
		body = `{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"compact"}]},{"type":"compaction_trigger"}]}`
	} else if kind == "replay" {
		body = `{"input":` + gjson.GetBytes(output, "output").Raw + `}`
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse, OriginalRequest: []byte(body)}
	if kind == "compact" {
		opts.Alt = "responses/compact"
	}
	return cliproxyexecutor.Request{Model: "claude-sonnet-4-6", Payload: []byte(body)}, opts
}

func executeCompactionCredits(manager *Manager, kind string, output []byte) (cliproxyexecutor.Response, error) {
	req, opts := compactionCreditsRequest(kind, output)
	return manager.Execute(context.Background(), []string{"antigravity"}, req, opts)
}

func assertCompactionCreditsProduction(t *testing.T, calls []compactionCreditsCall, firstID, secondID string) {
	t.Helper()
	want := []compactionCreditsCall{{authID: firstID}, {authID: secondID}, {authID: firstID, credits: true}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("production calls = %+v, want normal A, normal B, credits A: %+v", calls, want)
	}
}

func TestManagerCompactionCreditsFallbackProductionReplayAndRestart(t *testing.T) {
	for _, kind := range []string{"compact", "trigger"} {
		t.Run(kind, func(t *testing.T) {
			firstID, secondID := t.Name()+"-A", t.Name()+"-B"
			fallback := &compactionAffinityFallback{preferredID: firstID}
			statePath := filepath.Join(t.TempDir(), "affinity.state")
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: fallback, StatePath: statePath})
			defer selector.Stop()
			executor := &compactionCreditsExecutor{output: []byte(creditsCompactionResponse)}
			manager := newCompactionCreditsManager(t, selector, executor, firstID, secondID)
			// Result policy executes at the start of MarkResult: evidence must
			// already exist, even before success counters or hooks are published.
			creditsSuccesses := 0
			manager.SetResultPolicy(ResultPolicyFunc(func(ctx context.Context, result Result) Result {
				if AntigravityCreditsRequested(ctx) && result.Success {
					creditsSuccesses++
					capsule := gjson.GetBytes(executor.output, "output.0.encrypted_content").String()
					key := fmt.Sprintf("compaction::%x", sha256.Sum256([]byte(capsule)))
					if signer, known := selector.cache.Get(key); !known || signer != firstID || !selector.cache.IsProtected(key) {
						t.Fatalf("credits success published before actual-A signer registration: %q, %v", signer, known)
					}
				}
				return result
			}))
			produced, errProduce := executeCompactionCredits(manager, kind, nil)
			if errProduce != nil || string(produced.Payload) != creditsCompactionResponse {
				t.Fatalf("credits compaction production = %s, %v", produced.Payload, errProduce)
			}
			assertCompactionCreditsProduction(t, executor.calls, firstID, secondID)
			if creditsSuccesses != 1 {
				t.Fatalf("credits success records = %d, want 1", creditsSuccesses)
			}

			// No explicit session, pin or reused metadata. First fresh replay
			// must recover the producing signer even while fallback prefers B.
			fallback.preferredID = secondID
			executor.normalSucceeds = true
			executor.calls = nil
			if _, errReplay := executeCompactionCredits(manager, "replay", produced.Payload); errReplay != nil {
				t.Fatalf("first fresh replay: %v", errReplay)
			}
			wantReplay := []compactionCreditsCall{{authID: firstID, pinned: firstID}}
			if !reflect.DeepEqual(executor.calls, wantReplay) {
				t.Fatalf("fresh replay calls = %+v, want %+v", executor.calls, wantReplay)
			}

			selector.Stop()
			restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
				Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
			})
			defer restarted.Stop()
			manager = newCompactionCreditsManager(t, restarted, executor, firstID, secondID)
			executor.normalSucceeds = false
			executor.creditsFailID = firstID
			executor.calls = nil
			// B has known credits and would succeed if the separate credits
			// candidate path ignored the signer pin from PrepareCompactionRequest.
			SetAntigravityCreditsHint(secondID, AntigravityCreditsHint{Known: true, Available: true})
			failed, errReplay := executeCompactionCredits(manager, "replay", produced.Payload)
			if errReplay == nil || len(failed.Payload) != 0 {
				t.Fatalf("forced actual-A failure delivered a response: %s, %v", failed.Payload, errReplay)
			}
			wantFailure := []compactionCreditsCall{{authID: firstID, pinned: firstID}, {authID: firstID, pinned: firstID, credits: true}}
			if !reflect.DeepEqual(executor.calls, wantFailure) {
				t.Fatalf("restart failure calls = %+v, want only normal A and credits A: %+v", executor.calls, wantFailure)
			}
			// Existing credits semantics retain the last normal error if all
			// credits attempts fail; do not alter that behavior in this fix.
			var statusErr cliproxyexecutor.StatusError
			if !errors.As(errReplay, &statusErr) || statusErr.StatusCode() != http.StatusTooManyRequests {
				t.Fatalf("restart error = %v, want normal quota failure", errReplay)
			}
		})
	}
}

type compactionCreditsHook struct {
	NoopHook
	results []Result
}

func (h *compactionCreditsHook) OnResult(_ context.Context, result Result) {
	h.results = append(h.results, result)
}

func TestManagerCompactionCreditsFallbackRegistrationFailureIsLocalStop(t *testing.T) {
	firstID, secondID := t.Name()+"-A", t.Name()+"-B"
	selector := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: firstID})
	defer selector.Stop()
	executor := &compactionCreditsExecutor{output: []byte(creditsCompactionResponse)}
	manager := newCompactionCreditsManager(t, selector, executor, firstID, secondID)
	hook := &compactionCreditsHook{}
	manager.hook = hook
	policyCalls := 0
	manager.SetResultPolicy(ResultPolicyFunc(func(_ context.Context, result Result) Result {
		policyCalls++
		return result
	}))
	store := &recordingCooldownStore{}
	manager.SetCooldownStateStore(store)
	var beforeA, beforeB *Auth
	var beforeCooldown []CooldownStateRecord
	var beforePolicy, beforeHook int
	executor.beforeReturn = func() {
		// Fail strictly after normal attempts have exhausted and the credits
		// upstream has succeeded. Existing upstream-failure accounting stays.
		beforeA, _ = manager.GetByID(firstID)
		beforeB, _ = manager.GetByID(secondID)
		beforeCooldown = store.getRecords()
		beforePolicy, beforeHook = policyCalls, len(hook.results)
		selector.cache.mu.Lock()
		selector.cache.persistenceErr = errors.New("credits signer disk save failed")
		selector.cache.mu.Unlock()
	}
	resp, errSave := executeCompactionCredits(manager, "compact", nil)
	if !reflect.DeepEqual(resp, cliproxyexecutor.Response{}) {
		t.Fatalf("local save failure delivered payload/headers: %+v", resp)
	}
	var statusErr cliproxyexecutor.StatusError
	var authErr *Error
	if !errors.As(errSave, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable ||
		!errors.As(errSave, &authErr) || authErr.Code != "affinity_state_unavailable" ||
		!isRequestStopError(errSave) || !IsLocalCompactionAffinityStop(fmt.Errorf("HTTP wrapper: %w", errSave)) {
		t.Fatalf("local save failure lost status/code/request-stop marker: %v", errSave)
	}
	assertCompactionCreditsProduction(t, executor.calls, firstID, secondID)
	if beforeA == nil || beforeB == nil || beforePolicy != 2 || beforeHook != 2 {
		t.Fatalf("failure injection did not reach credits after both normal failures: policy=%d hook=%d", beforePolicy, beforeHook)
	}
	if policyCalls != beforePolicy || len(hook.results) != beforeHook {
		t.Fatalf("local failure reached auth policy/hook: policy %d -> %d, hook %d -> %d", beforePolicy, policyCalls, beforeHook, len(hook.results))
	}
	afterA, _ := manager.GetByID(firstID)
	afterB, _ := manager.GetByID(secondID)
	if !reflect.DeepEqual(beforeA, afterA) || !reflect.DeepEqual(beforeB, afterB) {
		t.Fatalf("local failure changed auth counters/availability/cooldown: A before=%+v after=%+v; B before=%+v after=%+v", beforeA, afterA, beforeB, afterB)
	}
	if !reflect.DeepEqual(beforeCooldown, store.getRecords()) {
		t.Fatal("local failure changed persisted cooldown state")
	}
}

func TestManagerNoncompactionCreditsFallbackSuccessStillAllowsB(t *testing.T) {
	firstID, secondID := t.Name()+"-A", t.Name()+"-B"
	selector := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: firstID})
	defer selector.Stop()
	executor := &compactionCreditsExecutor{creditsFailID: firstID, output: []byte(creditsOrdinaryResponse)}
	manager := newCompactionCreditsManager(t, selector, executor, firstID, secondID)
	hook := &compactionCreditsHook{}
	manager.hook = hook
	resp, errExecute := executeCompactionCredits(manager, "ordinary", nil)
	if errExecute != nil || string(resp.Payload) != creditsOrdinaryResponse || resp.Headers.Get("X-Credits-Test") != "produced" {
		t.Fatalf("ordinary credits success changed: %+v, %v", resp, errExecute)
	}
	want := []compactionCreditsCall{{authID: firstID}, {authID: secondID}, {authID: firstID, credits: true}, {authID: secondID, credits: true}}
	if !reflect.DeepEqual(executor.calls, want) {
		t.Fatalf("ordinary credits calls = %+v, want %+v", executor.calls, want)
	}
	if len(hook.results) != 4 || !hook.results[3].Success || hook.results[3].AuthID != secondID {
		t.Fatalf("ordinary credits B success was not recorded: %+v", hook.results)
	}
	auth, _ := manager.GetByID(secondID)
	if auth.Success != 1 {
		t.Fatalf("ordinary credits success counter = %d, want 1", auth.Success)
	}
}
