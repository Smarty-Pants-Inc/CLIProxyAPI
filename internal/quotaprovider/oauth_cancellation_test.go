package quotaprovider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Done is consulted only after FetchQuota has joined the single-flight operation.
type waitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

type fetchResult struct {
	response pluginapi.QuotaFetchResponse
	err      error
}

func TestOAuthCanceledLeaderDoesNotCancelSharedFetch(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		t.Run(provider, func(t *testing.T) {
			var calls atomic.Int32
			entered, release := make(chan struct{}), make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				_, _ = io.WriteString(w, fixture[provider])
			}))
			defer server.Close()
			defer close(release)
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			leader := make(chan fetchResult, 1)
			go func() {
				response, err := p.FetchQuota(ctx, request(provider, "one"))
				leader <- fetchResult{response, err}
			}()
			<-entered
			waitCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			waiterCtx := &waitingContext{Context: waitCtx, waiting: make(chan struct{})}
			waiter := make(chan fetchResult, 1)
			go func() {
				response, err := p.FetchQuota(waiterCtx, request(provider, "one"))
				waiter <- fetchResult{response, err}
			}()
			<-waiterCtx.waiting
			cancel()
			result := <-leader
			if !errors.Is(result.err, context.Canceled) {
				t.Errorf("canceled leader error = %v, want context.Canceled", result.err)
			}
			// Let the surviving caller receive the actual upstream response.
			release <- struct{}{}
			result = <-waiter
			if result.err != nil || result.response.Status != "known" {
				t.Fatalf("surviving caller = %+v, want known quota", result)
			}
			cached := fetch(t, p, request(provider, "one"))
			if cached.Status != "known" || calls.Load() != 1 {
				t.Fatalf("cache = %+v, upstream calls = %d; want real cached quota and one call", cached, calls.Load())
			}
		})
	}
}

func TestOAuthStalledUpstreamTimesOutAndReleasesFlight(t *testing.T) {
	for _, stage := range []string{"headers", "body"} {
		t.Run(stage, func(t *testing.T) {
			var calls atomic.Int32
			canceled, stop := make(chan struct{}), make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					if stage == "body" {
						w.WriteHeader(http.StatusOK)
						w.(http.Flusher).Flush()
					}
					select {
					case <-r.Context().Done():
						close(canceled)
					case <-stop:
					}
					return
				}
				_, _ = io.WriteString(w, fixture["codex"])
			}))
			defer server.Close()
			defer close(stop)
			p := New(func(context.Context, pluginapi.QuotaFetchRequest) (Credential, error) {
				return Credential{Token: testToken, Transport: redirectedTransport(server)}, nil
			})
			p.requestTimeout = 50 * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			response, err := p.FetchQuota(ctx, request("codex", "one"))
			assertUnknown(t, response)
			if err != nil || time.Since(start) > time.Second {
				t.Fatalf("stalled %s request took %v, error %v; want unknown within bounded operation timeout", stage, time.Since(start), err)
			}
			select {
			case <-canceled:
			case <-ctx.Done():
				t.Fatal("timed-out upstream request was not canceled")
			}
			// Upstream timeouts are cached failures, but must not leave a stuck flight.
			p.mu.Lock()
			cached, ok := p.cache["codex:one"]
			delete(p.cache, "codex:one")
			p.mu.Unlock()
			if !ok || cached.response.Status != "unknown" {
				t.Fatal("upstream timeout not cached as unknown")
			}
			response, err = p.FetchQuota(ctx, request("codex", "one"))
			if err != nil || response.Status != "known" || calls.Load() != 2 {
				t.Fatalf("flight not released: response=%+v error=%v calls=%d", response, err, calls.Load())
			}
		})
	}
}
