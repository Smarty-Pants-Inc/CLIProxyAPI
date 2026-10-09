package live

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// A failed join must release its parent-call registration, not just the handler's
// raw relay owner. Invoke the handler synchronously so all defers have completed.
func TestSidebandFailedRetriesReleaseCallResources(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, failure := range []string{"credential unavailable", "handshake rejected"} {
		t.Run(failure, func(t *testing.T) {
			for _, path := range []string{"/v1/live/call", "/v1/realtime/calls/call", "/v1/realtime?call_id=call"} {
				t.Run(path, func(t *testing.T) {
					var upstreamCalls atomic.Int32
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						upstreamCalls.Add(1)
						if r.Header.Get("Authorization") != "Bearer synthetic" {
							t.Error("upstream did not use the pinned credential")
						}
						w.WriteHeader(http.StatusForbidden)
					}))
					defer upstream.Close()
					manager := auth.NewManager(nil, nil, nil)
					manager.RegisterExecutor(&captureExecutor{})
					credentialID := "pinned"
					if failure == "credential unavailable" {
						credentialID = "other"
					}
					registerCredential(t, manager, &auth.Auth{ID: credentialID, Provider: "codex", Status: auth.StatusActive, Metadata: map[string]any{"access_token": "synthetic"}})
					h := NewHandler(manager, nil)
					defer h.Close()
					h.sidebandAPIBaseURL = "ws" + strings.TrimPrefix(upstream.URL, "http") + "/v1"
					stored := h.sessions.put("call", liveSession{authID: "pinned", model: defaultLiveModel, ownerPrincipal: "owner", ownerProvider: "config-api-key"})
					var baselineClosed atomic.Bool
					stored.resources.add(func() error { baselineClosed.Store(true); return nil })
					baseline := len(stored.resources.closers)
					router := gin.New()
					next := func(c *gin.Context) {
						c.Set("userApiKey", "owner")
						c.Set("accessProvider", "config-api-key")
						if c.Request.URL.Path == "/v1/realtime" {
							h.HandleRealtimeWebsocket(c)
						} else {
							h.HandleSideband(c)
						}
					}
					router.GET("/v1/live/:call_id", next)
					router.GET("/v1/realtime/calls/:call_id", next)
					router.GET("/v1/realtime", next)
					const retries = 16
					for i := 0; i < retries; i++ {
						req := httptest.NewRequest(http.MethodGet, path, nil)
						req.Header.Set("Connection", "Upgrade")
						req.Header.Set("Upgrade", "websocket")
						req.Header.Set("Sec-WebSocket-Version", "13")
						req.Header.Set("Sec-WebSocket-Key", "c3ludGhldGljLWtleS0xMg==")
						rr := httptest.NewRecorder()
						router.ServeHTTP(rr, req)
						wantStatus := http.StatusServiceUnavailable
						if failure == "handshake rejected" {
							wantStatus = http.StatusForbidden
						}
						if rr.Code != wantStatus {
							t.Fatalf("attempt %d: status=%d, want %d; body=%s", i, rr.Code, wantStatus, rr.Body.String())
						}
						stored.resources.mu.Lock()
						registrations, closed := len(stored.resources.closers), stored.resources.closed
						stored.resources.mu.Unlock()
						if registrations != baseline {
							t.Errorf("attempt %d retained %d call resource registrations, want baseline %d", i, registrations, baseline)
						}
						if closed || baselineClosed.Load() {
							t.Fatal("failed retry closed the retained call's baseline resources")
						}
						h.mediaRelayMu.Lock()
						owners := len(h.rawRelayOwners)
						h.mediaRelayMu.Unlock()
						if owners != 0 {
							t.Fatalf("attempt %d retained %d raw relay owners", i, owners)
						}
						retry, claim := h.sessions.claim("call")
						if claim != sessionClaimAcquired || retry.token != stored.token || retry.resources != stored.resources {
							t.Fatalf("attempt %d: retained call is not retryable: claim=%v", i, claim)
						}
						h.sessions.release(retry)
					}
					wantCalls := int32(0)
					if failure == "handshake rejected" {
						wantCalls = retries
					}
					if got := upstreamCalls.Load(); got != wantCalls {
						t.Fatalf("upstream calls=%d, want %d", got, wantCalls)
					}
				})
			}
		})
	}
}

// Detaching a completed attempt must not remove neighboring registrations or
// leave its closure reachable through the parent's slice backing array.
func TestLiveSessionResourcesRemoveCompletedAttempt(t *testing.T) {
	parent, attempt := &liveSessionResources{}, &liveSessionResources{}
	var baselineCalls, attemptCalls atomic.Int32
	parent.add(func() error { baselineCalls.Add(1); return nil })
	attempt.add(func() error { attemptCalls.Add(1); return nil })
	unregister := parent.add(func() error { attempt.close(); return nil })
	parent.add(func() error { baselineCalls.Add(1); return nil })
	attempt.close()
	unregister()
	unregister() // Removal is idempotent.
	parent.mu.Lock()
	registrations := len(parent.closers)
	backing := parent.closers[:cap(parent.closers)]
	for i := registrations; i < len(backing); i++ {
		if backing[i] != nil {
			t.Error("removed resource remains reachable through slice capacity")
		}
	}
	parent.mu.Unlock()
	if registrations != 2 {
		t.Fatalf("registrations=%d, want two baseline resources", registrations)
	}
	parent.close()
	parent.close()
	if baselineCalls.Load() != 2 || attemptCalls.Load() != 1 {
		t.Fatalf("close counts baseline/attempt=%d/%d, want 2/1", baselineCalls.Load(), attemptCalls.Load())
	}
}

// Once completion has captured registrations, concurrent removal must not
// prevent it from cancelling a still-active attempt. Block the first closer to
// force removal between capture and invocation, without wall-clock ordering.
func TestLiveSessionResourcesCloseOwnsConcurrentRemoval(t *testing.T) {
	parent, attempt := &liveSessionResources{}, &liveSessionResources{}
	captured, proceed, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	parent.add(func() error { close(captured); <-proceed; return nil })
	var cancelled atomic.Bool
	attempt.add(func() error { cancelled.Store(true); return nil })
	unregister := parent.add(func() error { attempt.close(); return nil })
	go func() { parent.close(); close(finished) }()
	// Always release and join the closer, including on a failed assertion.
	defer func() {
		close(proceed)
		waitLiveEvent(t, finished, "concurrent resource close completion")
		if !cancelled.Load() {
			t.Error("concurrent removal prevented completion from cancelling the active attempt")
		}
	}()
	waitLiveEvent(t, captured, "completion capturing attempt ownership")
	unregister()
	// Completion still owns the attempt even though the live registry is empty.
	parent.mu.Lock()
	registrations := len(parent.closers)
	parent.mu.Unlock()
	if registrations != 0 {
		t.Errorf("closed parent retained %d registrations", registrations)
	}
}

func TestLiveSessionResourcesLateAttachmentClosesImmediately(t *testing.T) {
	parent, attempt := &liveSessionResources{}, &liveSessionResources{}
	parent.close()
	var cancelled, socketClosed atomic.Bool
	attempt.add(func() error { cancelled.Store(true); return nil })
	unregister := parent.add(func() error { attempt.close(); return nil })
	if !cancelled.Load() {
		t.Fatal("attachment to completed call did not cancel attempt immediately")
	}
	attempt.add(func() error { socketClosed.Store(true); return nil })
	if !socketClosed.Load() {
		t.Fatal("late socket attachment to cancelled attempt did not close immediately")
	}
	unregister()
	parent.mu.Lock()
	registrations := len(parent.closers)
	parent.mu.Unlock()
	if registrations != 0 {
		t.Fatalf("late attachment left %d call registrations", registrations)
	}
}
