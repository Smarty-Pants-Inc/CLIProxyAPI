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
