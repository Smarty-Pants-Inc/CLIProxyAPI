package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// CodexExecutor.HttpRequest must apply a redirect policy carried on the
// context, so the quota re-probe cannot follow a redirect off its origin.
func TestCodexExecutorHttpRequest_AppliesContextRedirectPolicy(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherHits.Add(1)
		_, _ = io.WriteString(w, "{}")
	}))
	defer other.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/wham/usage", http.StatusFound)
	}))
	defer origin.Close()

	errRefused := errors.New("refused")
	var policyCalls atomic.Int32
	ctx := cliproxyauth.WithHTTPRedirectPolicy(context.Background(), func(*http.Request, []*http.Request) error {
		policyCalls.Add(1)
		return errRefused
	})
	//nolint:staticcheck // the executor reads the round tripper from this string key
	ctx = context.WithValue(ctx, "cliproxy.roundtripper", origin.Client().Transport)

	req, errReq := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL+"/wham/usage", nil)
	if errReq != nil {
		t.Fatal(errReq)
	}
	auth := &cliproxyauth.Auth{ID: "codex-a", Provider: "codex", Metadata: map[string]any{"access_token": "tok"}}
	resp, errDo := NewCodexExecutor(nil).HttpRequest(ctx, auth, req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if !errors.Is(errDo, errRefused) {
		t.Fatalf("HttpRequest error = %v, want the policy's refusal", errDo)
	}
	if policyCalls.Load() != 1 || otherHits.Load() != 0 {
		t.Fatalf("policy calls = %d, other host hits = %d; want 1 and 0", policyCalls.Load(), otherHits.Load())
	}
}
