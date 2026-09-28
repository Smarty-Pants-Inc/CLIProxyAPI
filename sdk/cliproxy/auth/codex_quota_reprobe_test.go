package auth

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

type codexUsageProbeExecutor struct {
	codexOnlyFailureExecutor
	mu     sync.Mutex
	bodies map[string]string
	seen   map[string]string // auth ID -> Chatgpt-Account-Id header
	urls   []string
	calls  []string
	// pauseFirst, when set, blocks the first probe: started is closed when it
	// begins and the probe waits for resume.
	pauseFirst bool
	started    chan struct{}
	resume     chan struct{}
}

func (e *codexUsageProbeExecutor) HttpRequest(_ context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	e.seen[auth.ID] = req.Header.Get("Chatgpt-Account-Id")
	e.urls = append(e.urls, req.URL.String())
	e.calls = append(e.calls, auth.ID)
	first := len(e.calls) == 1
	body := e.bodies[auth.ID]
	if body == "" {
		body = e.bodies["*"]
	}
	e.mu.Unlock()
	if e.pauseFirst && first {
		close(e.started)
		<-e.resume
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(body))}, nil
}

func (e *codexUsageProbeExecutor) probedIDs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

func newPausingUsageExecutor(body string) *codexUsageProbeExecutor {
	return &codexUsageProbeExecutor{
		bodies:     map[string]string{"*": body},
		seen:       map[string]string{},
		pauseFirst: true,
		started:    make(chan struct{}),
		resume:     make(chan struct{}),
	}
}

func heldCodexAuth(id string, holdUntil time.Time) *Auth {
	return &Auth{
		ID: id, Provider: "codex", Status: StatusError, Metadata: map[string]any{"account_id": "acct-" + id},
		Unavailable: true, NextRetryAfter: holdUntil,
		LastError: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"},
		Quota:     QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: holdUntil},
	}
}

func TestCodexUsageAllows(t *testing.T) {
	cases := map[string]bool{
		`{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":12}}}`: true,
		`{"rate_limit":{"allowed":true}}`:                        true,
		`{"rate_limit":{"allowed":true,"limit_reached":true}}`:   false,
		`{"rate_limit":{"allowed":false,"limit_reached":false}}`: false,
		// Missing, null or non-boolean "allowed" is not approval.
		`{"rate_limit":{"limit_reached":false}}`:                  false,
		`{"rate_limit":{"allowed":null,"limit_reached":false}}`:   false,
		`{"rate_limit":{"allowed":"true","limit_reached":false}}`: false,
		`{"rate_limit":{"allowed":1,"limit_reached":false}}`:      false,
		`{"rate_limit":{}}`:   false,
		`{"rate_limit":null}`: false,
		`{"rate_limit":{"primary_window":{"used_percent":100}}}`: false,
		`{"plan_type":"pro"}`: false,
		`not json`:            false,
		// A separately limited feature reported exhausted keeps the hold.
		`{"rate_limit":{"allowed":true,"limit_reached":false},"additional_rate_limits":[{"limit_name":"GPT-5.3-Codex-Spark","rate_limit":{"allowed":false,"limit_reached":true}}]}`: false,
		`{"rate_limit":{"allowed":true,"limit_reached":false},"additional_rate_limits":[{"limit_name":"GPT-5.3-Codex-Spark","rate_limit":{"allowed":true,"limit_reached":false}}]}`: true,
	}
	for body, want := range cases {
		if got := codexUsageAllows([]byte(body)); got != want {
			t.Errorf("codexUsageAllows(%s) = %v, want %v", body, got, want)
		}
	}
}

func TestReprobeHeldCodexQuotas_ReleasesOnlyAccountsUsageShowsAvailable(t *testing.T) {
	executor := &codexUsageProbeExecutor{
		bodies: map[string]string{
			"codex-free":    `{"rate_limit":{"allowed":true,"limit_reached":false}}`,
			"codex-full":    `{"rate_limit":{"allowed":false,"limit_reached":true}}`,
			"codex-unknown": `{"rate_limit":{"limit_reached":false}}`,
		},
		seen: map[string]string{},
	}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	for _, id := range []string{"codex-free", "codex-full", "codex-unknown", "codex-ok"} {
		auth := heldCodexAuth(id, holdUntil)
		if id == "codex-ok" {
			auth = &Auth{ID: id, Provider: "codex", Status: StatusActive}
		}
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}

	released := manager.reprobeHeldCodexQuotas(context.Background())

	if len(released) != 1 || released[0] != "codex-free" {
		t.Fatalf("released = %v, want [codex-free]", released)
	}
	if _, probed := executor.seen["codex-ok"]; probed {
		t.Fatal("an account that is not held must not be probed")
	}
	if got := executor.seen["codex-free"]; got != "acct-codex-free" {
		t.Fatalf("Chatgpt-Account-Id = %q, want acct-codex-free", got)
	}
	for _, u := range executor.urls {
		if u != codexUsageURL {
			t.Fatalf("probe URL = %q, want %q", u, codexUsageURL)
		}
	}
	free, _ := manager.GetByID("codex-free")
	if free.Quota.Exceeded || free.Unavailable || !free.Quota.NextRecoverAt.IsZero() || free.Status != StatusActive {
		t.Fatalf("codex-free still held: quota=%+v unavailable=%v status=%s", free.Quota, free.Unavailable, free.Status)
	}
	for _, id := range []string{"codex-full", "codex-unknown"} {
		kept, _ := manager.GetByID(id)
		if !kept.Quota.Exceeded || !kept.Quota.NextRecoverAt.Equal(holdUntil) || !kept.Unavailable {
			t.Fatalf("%s hold changed: %+v", id, kept.Quota)
		}
	}
}

// A usage verdict releases only the quota hold: a sibling model-support failure,
// an operator-forced cooldown and a disabled model state stay exactly as they were.
func TestReprobeHeldCodexQuotas_ReleasesOnlyTheQuotaHold(t *testing.T) {
	executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": `{"rate_limit":{"allowed":true,"limit_reached":false}}`}, seen: map[string]string{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	now := time.Now()
	holdUntil := now.Add(72 * time.Hour)
	auth := &Auth{ID: "codex-mixed", Provider: "codex", Status: StatusError, ModelStates: map[string]*ModelState{
		"gpt-5.5": {
			Status: StatusError, Unavailable: true, NextRetryAfter: holdUntil, StatusMessage: "usage_limit_reached",
			LastError: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"},
			Quota:     QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: holdUntil},
		},
		"gpt-unsupported": {
			Status: StatusError, Unavailable: true, NextRetryAfter: now.Add(12 * time.Hour), StatusMessage: "model_not_supported",
			LastError: &Error{HTTPStatus: http.StatusNotFound, Message: "model_not_supported"},
		},
		"gpt-forced": {
			Status: StatusError, Unavailable: true, NextRetryAfter: now.Add(2 * time.Hour), StatusMessage: "forced",
			LastError: &Error{Code: ErrorCodeForceCooldown, HTTPStatus: http.StatusTooManyRequests, Message: "forced"},
			Quota:     QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: now.Add(2 * time.Hour)},
		},
		"gpt-disabled": {Status: StatusDisabled, Unavailable: true},
	}}
	updateAggregatedAvailability(auth, now)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	before, _ := manager.GetByID("codex-mixed")

	released := manager.reprobeHeldCodexQuotas(context.Background())
	if len(released) != 1 {
		t.Fatalf("released = %v, want [codex-mixed]", released)
	}
	after, _ := manager.GetByID("codex-mixed")
	if !modelStateIsClean(after.ModelStates["gpt-5.5"]) {
		t.Fatalf("quota-held model not released: %+v", after.ModelStates["gpt-5.5"])
	}
	for _, model := range []string{"gpt-unsupported", "gpt-forced", "gpt-disabled"} {
		if !reflect.DeepEqual(before.ModelStates[model], after.ModelStates[model]) {
			t.Fatalf("%s changed:\nbefore %+v\nafter  %+v", model, before.ModelStates[model], after.ModelStates[model])
		}
	}
	if after.Unavailable {
		t.Fatal("account must be routable again for the released model")
	}
	if after.Status != StatusError {
		t.Fatalf("account status = %s, want error while model errors remain", after.Status)
	}
}

// Pause the first probe, disable or remove every other queued account, and no
// request may start for them.
func TestReprobeHeldCodexQuotas_SkipsAccountsWithdrawnWhileQueued(t *testing.T) {
	executor := newPausingUsageExecutor(`{"rate_limit":{"allowed":true,"limit_reached":false}}`)
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	ids := []string{"codex-a", "codex-b", "codex-c"}
	for _, id := range ids {
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth(id, holdUntil)); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	done := make(chan []string, 1)
	go func() { done <- manager.reprobeHeldCodexQuotas(context.Background()) }()
	<-executor.started
	first := executor.probedIDs()[0]
	withdrawn := 0
	for _, id := range ids {
		if id == first {
			continue
		}
		if withdrawn == 0 {
			disabled, _ := manager.GetByID(id)
			disabled.Disabled = true
			disabled.Status = StatusDisabled
			if _, errUpdate := manager.Update(WithSkipPersist(context.Background()), disabled); errUpdate != nil {
				t.Fatalf("disable %s: %v", id, errUpdate)
			}
		} else {
			manager.Remove(WithSkipPersist(context.Background()), id)
		}
		withdrawn++
	}
	close(executor.resume)
	released := <-done
	if got := executor.probedIDs(); len(got) != 1 || got[0] != first {
		t.Fatalf("probed %v, want only %s: withdrawn accounts must not be used", got, first)
	}
	if len(released) != 1 || released[0] != first {
		t.Fatalf("released = %v, want [%s]", released, first)
	}
}

// A successful probe of one registration must not release a hold on a
// replacement registered under the same ID while the probe was in flight.
func TestReprobeHeldCodexQuotas_DropsResultForReplacedCredential(t *testing.T) {
	executor := newPausingUsageExecutor(`{"rate_limit":{"allowed":true,"limit_reached":false}}`)
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth("codex-x", time.Now().Add(72*time.Hour))); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	done := make(chan []string, 1)
	go func() { done <- manager.reprobeHeldCodexQuotas(context.Background()) }()
	<-executor.started
	manager.Remove(WithSkipPersist(context.Background()), "codex-x")
	newHold := time.Now().Add(96 * time.Hour).Round(time.Second)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth("codex-x", newHold)); errRegister != nil {
		t.Fatalf("re-register: %v", errRegister)
	}
	close(executor.resume)
	if released := <-done; len(released) != 0 {
		t.Fatalf("released = %v, want none", released)
	}
	replacement, _ := manager.GetByID("codex-x")
	if !replacement.Quota.Exceeded || !replacement.Quota.NextRecoverAt.Equal(newHold) || !replacement.Unavailable {
		t.Fatalf("replacement's hold was cleared by the old probe: %+v", replacement.Quota)
	}
}

// A probe result that arrives after the lifecycle was cancelled is not applied.
func TestReprobeHeldCodexQuotas_CancelledBeforeApplyKeepsHold(t *testing.T) {
	executor := newPausingUsageExecutor(`{"rate_limit":{"allowed":true,"limit_reached":false}}`)
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth("codex-y", holdUntil)); errRegister != nil {
		t.Fatalf("register: %v", errRegister)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []string, 1)
	go func() { done <- manager.reprobeHeldCodexQuotas(ctx) }()
	<-executor.started
	cancel()
	close(executor.resume)
	if released := <-done; len(released) != 0 {
		t.Fatalf("released = %v, want none after cancellation", released)
	}
	held, _ := manager.GetByID("codex-y")
	if !held.Quota.Exceeded || !held.Quota.NextRecoverAt.Equal(holdUntil) {
		t.Fatalf("hold cleared after cancellation: %+v", held.Quota)
	}
}

// A credential-wide failure recorded on top of a quota hold (MarkResult with an
// empty model) is an independent restriction. applyAuthFailureState folds its
// shorter deadline into the quota deadline, so an "allowed" usage probe must
// not take that as proof the account is only quota-held: the whole hold stays.
func TestReprobeHeldCodexQuotas_KeepsHoldWithAuthLevelFailure(t *testing.T) {
	quota429 := func() *Error {
		return &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"}
	}
	cases := []struct {
		name            string
		credentialScope bool
		authErr         *Error
	}{
		{"credential-quota+403", true, &Error{HTTPStatus: http.StatusForbidden, Message: "account deactivated"}},
		{"credential-quota+forced-cooldown", true, &Error{Code: ErrorCodeForceCooldown, HTTPStatus: http.StatusBadRequest, Message: "forced"}},
		{"model-quota+403", false, &Error{HTTPStatus: http.StatusForbidden, Message: "account deactivated"}},
		{"model-quota+forced-cooldown", false, &Error{Code: ErrorCodeForceCooldown, HTTPStatus: http.StatusBadRequest, Message: "forced"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": `{"rate_limit":{"allowed":true,"limit_reached":false}}`}, seen: map[string]string{}}
			manager := NewManager(nil, nil, nil)
			manager.RegisterExecutor(executor)
			ctx := WithSkipPersist(context.Background())
			auth := &Auth{ID: "codex-held", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"account_id": "acct-held"}}
			if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
				t.Fatalf("register: %v", errRegister)
			}
			reset := 72 * time.Hour
			manager.MarkResult(ctx, Result{AuthID: "codex-held", Provider: "codex", Model: "gpt-5.5", RetryAfter: &reset, CredentialScope: tc.credentialScope, Error: quota429()})
			held, _ := manager.GetByID("codex-held")
			if !codexQuotaHeld(held, time.Now()) {
				t.Fatalf("setup: account not quota-held: %+v", held.Quota)
			}
			manager.MarkResult(ctx, Result{AuthID: "codex-held", Provider: "codex", Error: cloneError(tc.authErr)})
			before, _ := manager.GetByID("codex-held")
			if !codexQuotaHeld(before, time.Now()) || !before.Unavailable {
				t.Fatalf("setup: auth-level failure removed the quota hold: quota=%+v unavailable=%v", before.Quota, before.Unavailable)
			}

			released := manager.reprobeHeldCodexQuotas(context.Background())

			if len(executor.probedIDs()) != 1 {
				t.Fatalf("probes = %v, want one probe of codex-held", executor.probedIDs())
			}
			if len(released) != 0 {
				t.Fatalf("released = %v, want none: an auth-level %+v must keep the hold", released, tc.authErr)
			}
			after, _ := manager.GetByID("codex-held")
			if !reflect.DeepEqual(after.LastError, tc.authErr) {
				t.Fatalf("auth-level error cleared: LastError = %+v, want %+v", after.LastError, tc.authErr)
			}
			if !after.Unavailable || !after.NextRetryAfter.Equal(before.NextRetryAfter) || after.Status != StatusError {
				t.Fatalf("account released: unavailable=%v next=%v (was %v) status=%s", after.Unavailable, after.NextRetryAfter, before.NextRetryAfter, after.Status)
			}
			if !reflect.DeepEqual(before.Quota, after.Quota) || !reflect.DeepEqual(before.ModelStates, after.ModelStates) {
				t.Fatalf("hold changed:\nbefore quota=%+v states=%+v\nafter  quota=%+v states=%+v", before.Quota, before.ModelStates, after.Quota, after.ModelStates)
			}
		})
	}
}

// Control for the case above: the same manager transitions without the
// auth-level failure release the quota hold.
func TestReprobeHeldCodexQuotas_ReleasesQuotaOnlyHoldFromMarkResult(t *testing.T) {
	for _, credentialScope := range []bool{true, false} {
		executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": `{"rate_limit":{"allowed":true,"limit_reached":false}}`}, seen: map[string]string{}}
		manager := NewManager(nil, nil, nil)
		manager.RegisterExecutor(executor)
		ctx := WithSkipPersist(context.Background())
		if _, errRegister := manager.Register(ctx, &Auth{ID: "codex-held", Provider: "codex", Status: StatusActive}); errRegister != nil {
			t.Fatalf("register: %v", errRegister)
		}
		reset := 72 * time.Hour
		manager.MarkResult(ctx, Result{AuthID: "codex-held", Provider: "codex", Model: "gpt-5.5", RetryAfter: &reset, CredentialScope: credentialScope,
			Error: &Error{HTTPStatus: http.StatusTooManyRequests, Message: "usage_limit_reached"}})
		if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 1 {
			t.Fatalf("credentialScope=%v: released = %v, want [codex-held]", credentialScope, released)
		}
		after, _ := manager.GetByID("codex-held")
		if after.Unavailable || after.Quota.Exceeded || after.LastError != nil || after.Status != StatusActive {
			t.Fatalf("credentialScope=%v: still held: %+v", credentialScope, after)
		}
	}
}

// registerHeldCodexWithRegistry registers a quota-held Codex credential in the
// manager and its model in the global registry, with the registry quota marker set.
func registerHeldCodexWithRegistry(t *testing.T, manager *Manager, id, model string, holdUntil time.Time) {
	t.Helper()
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(id) })
	reg.SetModelQuotaExceeded(id, model)
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth(id, holdUntil)); errRegister != nil {
		t.Fatalf("register %s: %v", id, errRegister)
	}
}

// Security review P2: the registry publication after a release must be bound to
// the registration of the snapshot that was probed. Pause after the manager
// mutation and before the registry publication, replace the credential and its
// registry entry (new epoch) and restrict the replacement; the delayed
// publication must leave the replacement's markers and generation unchanged.
func TestReprobeHeldCodexQuotas_DelayedRegistryPublishSparesReplacement(t *testing.T) {
	const id, model = "codex-regbind", "gpt-5.5-regbind"
	executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": `{"rate_limit":{"allowed":true,"limit_reached":false}}`}, seen: map[string]string{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	registerHeldCodexWithRegistry(t, manager, id, model, time.Now().Add(72*time.Hour))
	reg := registry.GetGlobalRegistry()
	oldEpoch := reg.ClientRegistrationEpoch(id)

	newHold := time.Now().Add(96 * time.Hour).Round(time.Second)
	replaced := false
	codexQuotaBeforeRegistryPublish = func(authID string) {
		if authID != id {
			return
		}
		replaced = true
		manager.Remove(WithSkipPersist(context.Background()), id)
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth(id, newHold)); errRegister != nil {
			t.Errorf("re-register: %v", errRegister)
		}
		reg.UnregisterClient(id)
		reg.RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		reg.SetModelQuotaExceeded(id, model)
		reg.SuspendClientModel(id, model, "replacement-restriction")
	}
	t.Cleanup(func() { codexQuotaBeforeRegistryPublish = nil })

	released := manager.reprobeHeldCodexQuotas(context.Background())
	if !replaced {
		t.Fatal("the pause point before registry publication was not reached")
	}
	if len(released) != 1 {
		t.Fatalf("released = %v, want the old registration's manager release", released)
	}
	if reg.ClientRegistrationEpoch(id) == oldEpoch {
		t.Fatal("setup: replacement did not get a new registry epoch")
	}
	if !reg.IsModelQuotaExceededForClient(id, model) {
		t.Fatal("old snapshot cleared the replacement's registry quota marker")
	}
	if !reg.IsModelSuspendedForClient(id, model) {
		t.Fatal("old snapshot cleared the replacement's registry suspension")
	}
	// The replacement's registry generation is still 0: a generation-1 update
	// from the replacement is accepted. Had the old snapshot's (higher)
	// generation been installed, this would be rejected.
	if !reg.ApplyClientModelProjections(id, reg.ClientRegistrationEpoch(id), 1, []registry.ClientModelProjection{{ModelID: model, QuotaExceeded: true}}) {
		t.Fatal("old snapshot's generation was installed on the replacement's registry entry")
	}
	replacement, _ := manager.GetByID(id)
	if !replacement.Quota.Exceeded || !replacement.Quota.NextRecoverAt.Equal(newHold) || !replacement.Unavailable {
		t.Fatalf("replacement's manager hold changed: %+v", replacement.Quota)
	}
}

// Control for the case above: with no replacement the same path does publish
// the release to the registry, so the regression above is not vacuous.
func TestReprobeHeldCodexQuotas_RegistryPublishWithoutReplacement(t *testing.T) {
	const id, model = "codex-regpub", "gpt-5.5-regpub"
	executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": `{"rate_limit":{"allowed":true,"limit_reached":false}}`}, seen: map[string]string{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	registerHeldCodexWithRegistry(t, manager, id, model, time.Now().Add(72*time.Hour))
	reg := registry.GetGlobalRegistry()
	if !reg.IsModelQuotaExceededForClient(id, model) {
		t.Fatal("setup: registry quota marker not set")
	}
	if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 1 {
		t.Fatalf("released = %v, want [%s]", released, id)
	}
	if reg.IsModelQuotaExceededForClient(id, model) {
		t.Fatal("release was not published to the registry")
	}
}

// The interval override is clamped to the production minimum of 60s; invalid
// and non-positive values fall back to the hourly default.
func TestCodexQuotaReprobeIntervalFromEnv_ClampsToMinimum(t *testing.T) {
	cases := map[string]time.Duration{
		"":        codexQuotaReprobeInterval,
		"1s":      time.Minute,
		"59s":     time.Minute,
		"1ms":     time.Minute,
		"60s":     time.Minute,
		"90s":     90 * time.Second,
		"2h":      2 * time.Hour,
		"0":       codexQuotaReprobeInterval,
		"-5m":     codexQuotaReprobeInterval,
		"garbage": codexQuotaReprobeInterval,
	}
	if codexQuotaReprobeMinInterval != time.Minute {
		t.Fatalf("production minimum = %s, want 1m", codexQuotaReprobeMinInterval)
	}
	for raw, want := range cases {
		t.Setenv(codexQuotaReprobeIntervalEnv, raw)
		if got := codexQuotaReprobeIntervalFromEnv(); got != want {
			t.Errorf("%s=%q: interval = %s, want %s", codexQuotaReprobeIntervalEnv, raw, got, want)
		}
	}
}

// Only the in-package test hook can lower the floor.
func TestCodexQuotaReprobeIntervalFromEnv_TestHookLowersMinimum(t *testing.T) {
	prev := codexQuotaReprobeMinInterval
	codexQuotaReprobeMinInterval = time.Second
	t.Cleanup(func() { codexQuotaReprobeMinInterval = prev })
	t.Setenv(codexQuotaReprobeIntervalEnv, "5s")
	if got := codexQuotaReprobeIntervalFromEnv(); got != 5*time.Second {
		t.Fatalf("interval = %s, want 5s with the test hook", got)
	}
	t.Setenv(codexQuotaReprobeIntervalEnv, "10ms")
	if got := codexQuotaReprobeIntervalFromEnv(); got != time.Second {
		t.Fatalf("interval = %s, want the hooked 1s floor", got)
	}
}

// A cycle probes each held account at most once, and a cycle started while
// another is running is skipped rather than overlapping it.
func TestReprobeHeldCodexQuotas_OneProbePerAccountAndNoOverlap(t *testing.T) {
	executor := newPausingUsageExecutor(`{"rate_limit":{"allowed":false,"limit_reached":true}}`)
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	ids := []string{"codex-p1", "codex-p2", "codex-p3"}
	for _, id := range ids {
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth(id, holdUntil)); errRegister != nil {
			t.Fatalf("register %s: %v", id, errRegister)
		}
	}
	done := make(chan []string, 1)
	go func() { done <- manager.reprobeHeldCodexQuotas(context.Background()) }()
	<-executor.started
	if released := manager.reprobeHeldCodexQuotas(context.Background()); released != nil {
		t.Fatalf("overlapping cycle released %v", released)
	}
	if got := executor.probedIDs(); len(got) != 1 {
		t.Fatalf("overlapping cycle probed: %v", got)
	}
	close(executor.resume)
	<-done
	got := executor.probedIDs()
	counts := map[string]int{}
	for _, id := range got {
		counts[id]++
	}
	if len(got) != len(ids) {
		t.Fatalf("probes = %v, want each of %v once", got, ids)
	}
	for _, id := range ids {
		if counts[id] != 1 {
			t.Fatalf("%s probed %d times in one cycle, want 1 (all: %v)", id, counts[id], got)
		}
	}
	// The lock is released: the next cycle runs.
	manager.reprobeHeldCodexQuotas(context.Background())
	if n := len(executor.probedIDs()); n != 2*len(ids) {
		t.Fatalf("next cycle probes = %d, want %d", n, 2*len(ids))
	}
}
