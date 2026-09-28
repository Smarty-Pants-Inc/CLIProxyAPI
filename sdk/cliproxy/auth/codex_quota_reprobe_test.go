package auth

import (
	"context"
	"io"
	"net/http"
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
}

func (e *codexUsageProbeExecutor) HttpRequest(_ context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.seen[auth.ID] = req.Header.Get("Chatgpt-Account-Id")
	e.urls = append(e.urls, req.URL.String())
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Body: io.NopCloser(strings.NewReader(e.bodies[auth.ID]))}, nil
}

func TestCodexUsageAllows(t *testing.T) {
	cases := map[string]bool{
		`{"rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":12}}}`: true,
		`{"rate_limit":{"allowed":true}}`:                        true,
		`{"rate_limit":{"allowed":true,"limit_reached":true}}`:   false,
		`{"rate_limit":{"allowed":false,"limit_reached":false}}`: false,
		`{"rate_limit":{"primary_window":{"used_percent":100}}}`: false,
		`{"plan_type":"pro"}`:                                    false,
		`not json`:                                               false,
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
			"codex-free": `{"rate_limit":{"allowed":true,"limit_reached":false}}`,
			"codex-full": `{"rate_limit":{"allowed":false,"limit_reached":true}}`,
		},
		seen: map[string]string{},
	}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	for _, id := range []string{"codex-free", "codex-full", "codex-ok"} {
		auth := &Auth{ID: id, Provider: "codex", Status: StatusActive, Metadata: map[string]any{"account_id": "acct-" + id}}
		if id != "codex-ok" {
			auth.Unavailable = true
			auth.NextRetryAfter = holdUntil
			auth.Quota = QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: holdUntil}
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
	if free.Quota.Exceeded || free.Unavailable || !free.Quota.NextRecoverAt.IsZero() {
		t.Fatalf("codex-free still held: quota=%+v unavailable=%v", free.Quota, free.Unavailable)
	}
	full, _ := manager.GetByID("codex-full")
	if !full.Quota.Exceeded || !full.Quota.NextRecoverAt.Equal(holdUntil) {
		t.Fatalf("codex-full hold changed: %+v", full.Quota)
	}
}
