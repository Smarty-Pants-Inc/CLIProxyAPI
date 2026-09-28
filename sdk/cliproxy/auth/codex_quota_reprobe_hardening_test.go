package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const allowedUsageBody = `{"rate_limit":{"allowed":true,"limit_reached":false}}`

// httpUsageExecutor performs the probe over real HTTP and, like the Codex
// executor, applies the redirect policy the caller put on the context.
type httpUsageExecutor struct {
	codexOnlyFailureExecutor
	client *http.Client
}

func (e *httpUsageExecutor) HttpRequest(ctx context.Context, _ *Auth, req *http.Request) (*http.Response, error) {
	client := *e.client
	client.CheckRedirect = HTTPRedirectPolicyFromContext(ctx)
	return client.Do(req.WithContext(ctx))
}

func registerHeldCodex(t *testing.T, manager *Manager, id string, holdUntil time.Time) {
	t.Helper()
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), heldCodexAuth(id, holdUntil)); errRegister != nil {
		t.Fatalf("register %s: %v", id, errRegister)
	}
}

func setReprobeURL(t *testing.T, target string) {
	t.Helper()
	previous := codexQuotaReprobeURL
	codexQuotaReprobeURL = target
	t.Cleanup(func() { codexQuotaReprobeURL = previous })
}

func TestSameHostHTTPSRedirects(t *testing.T) {
	origin := &http.Request{URL: mustURL(t, "https://chatgpt.com/backend-api/wham/usage")}
	cases := map[string]bool{
		"https://chatgpt.com/backend-api/wham/usage2": true,
		"https://CHATGPT.com/other":                   true,
		"http://chatgpt.com/backend-api/wham/usage":   false,
		"https://evil.example/wham/usage":             false,
		"https://chatgpt.com:8443/wham/usage":         false,
		"https://chatgpt.com.evil.example/wham/usage": false,
	}
	for target, allowed := range cases {
		err := sameHostHTTPSRedirects(&http.Request{URL: mustURL(t, target)}, []*http.Request{origin})
		if (err == nil) != allowed {
			t.Errorf("redirect to %s: err=%v, want allowed=%v", target, err, allowed)
		}
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = origin
	}
	if sameHostHTTPSRedirects(&http.Request{URL: mustURL(t, "https://chatgpt.com/x")}, via) == nil {
		t.Error("an eleventh redirect must be refused")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A probe redirected to another host (or to plain http) is refused before the
// other host is contacted, and the quota hold is kept.
func TestReprobeHeldCodexQuotas_RefusesCrossHostAndHTTPRedirect(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherHits.Add(1)
		_, _ = io.WriteString(w, allowedUsageBody)
	}))
	defer other.Close()
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainHits.Add(1)
		_, _ = io.WriteString(w, allowedUsageBody)
	}))
	defer plain.Close()

	for name, target := range map[string]string{
		"cross-host https": other.URL + "/backend-api/wham/usage",
		"plain http":       plain.URL + "/backend-api/wham/usage",
	} {
		t.Run(name, func(t *testing.T) {
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer origin.Close()
			setReprobeURL(t, origin.URL+"/backend-api/wham/usage")
			manager := NewManager(nil, nil, nil)
			manager.RegisterExecutor(&httpUsageExecutor{client: origin.Client()})
			holdUntil := time.Now().Add(72 * time.Hour)
			registerHeldCodex(t, manager, "codex-r", holdUntil)

			held, _ := manager.GetByID("codex-r")
			if _, errProbe := manager.probeCodexUsage(context.Background(), held); errProbe == nil || !strings.Contains(errProbe.Error(), "refused redirect") {
				t.Fatalf("probe error = %v, want refused redirect", errProbe)
			}
			if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 0 {
				t.Fatalf("released = %v, want none", released)
			}
			kept, _ := manager.GetByID("codex-r")
			if !kept.Quota.Exceeded || !kept.Quota.NextRecoverAt.Equal(holdUntil) {
				t.Fatalf("hold changed after refused redirect: %+v", kept.Quota)
			}
		})
	}
	if otherHits.Load() != 0 || plainHits.Load() != 0 {
		t.Fatalf("redirect target contacted: other=%d plain=%d", otherHits.Load(), plainHits.Load())
	}
}

// A same-host https redirect is still followed.
func TestReprobeHeldCodexQuotas_FollowsSameHostHTTPSRedirect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/backend-api/wham/usage" {
			http.Redirect(w, r, "/backend-api/wham/usage/v2", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, allowedUsageBody)
	}))
	defer origin.Close()
	setReprobeURL(t, origin.URL+"/backend-api/wham/usage")
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(&httpUsageExecutor{client: origin.Client()})
	registerHeldCodex(t, manager, "codex-s", time.Now().Add(72*time.Hour))
	if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 1 {
		t.Fatalf("released = %v, want [codex-s]", released)
	}
}

// An executor that ignores the policy still cannot have an off-origin response
// accepted: the final response URL is checked against the probed origin.
func TestProbeCodexUsage_RejectsResponseFromAnotherOrigin(t *testing.T) {
	executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": allowedUsageBody}, seen: map[string]string{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(&offOriginExecutor{codexUsageProbeExecutor: executor})
	registerHeldCodex(t, manager, "codex-o", time.Now().Add(72*time.Hour))
	if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 0 {
		t.Fatalf("released = %v, want none", released)
	}
}

type offOriginExecutor struct{ *codexUsageProbeExecutor }

func (e *offOriginExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	resp, err := e.codexUsageProbeExecutor.HttpRequest(ctx, auth, req)
	if resp != nil {
		resp.Request = &http.Request{URL: &url.URL{Scheme: "https", Host: "evil.example", Path: "/wham/usage"}}
	}
	return resp, err
}

// A body over 1 MiB is refused instead of truncated and parsed. The padding is
// JSON whitespace, so the first 1 MiB alone would parse as "allowed".
func TestReprobeHeldCodexQuotas_RefusesOversizedUsageBody(t *testing.T) {
	oversized := allowedUsageBody + strings.Repeat(" ", codexUsageMaxBody+1-len(allowedUsageBody))
	if !codexUsageAllows([]byte(oversized[:codexUsageMaxBody])) {
		t.Fatal("test premise: the truncated body must parse as allowed")
	}
	executor := &codexUsageProbeExecutor{bodies: map[string]string{"*": oversized}, seen: map[string]string{}}
	manager := NewManager(nil, nil, nil)
	manager.RegisterExecutor(executor)
	holdUntil := time.Now().Add(72 * time.Hour)
	registerHeldCodex(t, manager, "codex-big", holdUntil)

	held, _ := manager.GetByID("codex-big")
	if _, errProbe := manager.probeCodexUsage(context.Background(), held); !errors.Is(errProbe, errCodexUsageBodyTooLarge) {
		t.Fatalf("probe error = %v, want errCodexUsageBodyTooLarge", errProbe)
	}
	if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 0 {
		t.Fatalf("released = %v, want none", released)
	}
	kept, _ := manager.GetByID("codex-big")
	if !kept.Quota.Exceeded || !kept.Quota.NextRecoverAt.Equal(holdUntil) {
		t.Fatalf("hold changed after oversized body: %+v", kept.Quota)
	}

	// Exactly 1 MiB is still accepted.
	executor.bodies["*"] = oversized[:codexUsageMaxBody]
	if released := manager.reprobeHeldCodexQuotas(context.Background()); len(released) != 1 {
		t.Fatalf("released = %v, want [codex-big] for a body of exactly 1 MiB", released)
	}
}
