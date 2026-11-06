package logging

import (
	"context"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Keep: the attempt/async boundary must never pair values with another acquisition.
func TestResponseHeadersObservation(t *testing.T) {
	ctx := WithResponseHeadersHolder(context.Background())
	t0, t1, t3 := time.Unix(100, 0), time.Unix(200, 0), time.Unix(400, 0)
	headers := http.Header{"X-Codex-Primary-Used-Percent": {"5"}, "X-Codex-Secondary-Used-Percent": {"20"}}
	original := headers.Clone()
	SetResponseHeadersAt(ctx, headers, t0)
	headers.Set("X-Codex-Primary-Used-Percent", "mutated")
	got, acquired := GetResponseHeadersObservation(ctx)
	if !reflect.DeepEqual(got, original) || len(acquired) != 2 {
		t.Fatalf("unpaired snapshot: headers=%v times=%v", got, acquired)
	}
	got.Set("X-Codex-Primary-Used-Percent", "caller mutation")
	acquired["X-Codex-Secondary-Used-Percent"] = t3
	MergeResponseHeadersAt(ctx, http.Header{"x-codex-primary-used-percent": {"5"}}, t1)
	got, acquired = GetResponseHeadersObservation(ctx)
	if !reflect.DeepEqual(got, original) || !acquired["X-Codex-Primary-Used-Percent"].Equal(t1) || !acquired["X-Codex-Secondary-Used-Percent"].Equal(t0) {
		t.Fatalf("partial/equal merge refreshed untouched evidence: %v %v", got, acquired)
	}
	MergeResponseHeadersAt(ctx, nil, t3)
	_, unchanged := GetResponseHeadersObservation(ctx)
	if !reflect.DeepEqual(unchanged, acquired) {
		t.Fatalf("empty merge changed acquisition: %v", unchanged)
	}
	SetResponseHeadersAt(ctx, http.Header{"x-codex-plan-type": {"pro"}}, t3)
	got, acquired = GetResponseHeadersObservation(ctx)
	if len(got) != 1 || len(acquired) != 1 || !acquired["X-Codex-Plan-Type"].Equal(t3) {
		t.Fatalf("Set did not replace values and canonical metadata: %v %v", got, acquired)
	}
	SetResponseHeadersAt(ctx, nil, time.Time{})
	got, acquired = GetResponseHeadersObservation(ctx)
	if len(got) != 0 || len(acquired) != 0 {
		t.Fatalf("clear retained observation: %v %v", got, acquired)
	}
}

func TestResponseHeadersObservationAtomicPairing(t *testing.T) {
	ctx := WithResponseHeadersHolder(context.Background())
	start := make(chan struct{})
	var writers sync.WaitGroup
	for writer := 0; writer < 2; writer++ {
		writers.Add(1)
		go func(writer int) {
			defer writers.Done()
			<-start
			for i := 1; i <= 100; i++ {
				n := int64(writer*100 + i)
				SetResponseHeadersAt(ctx, http.Header{"X-Pair": {strconv.FormatInt(n, 10)}}, time.Unix(n, 0))
			}
		}(writer)
	}
	close(start)
	for i := 0; i < 200; i++ {
		headers, times := GetResponseHeadersObservation(ctx)
		if len(headers) == 0 {
			continue
		}
		if headers.Get("X-Pair") != strconv.FormatInt(times["X-Pair"].Unix(), 10) {
			t.Errorf("torn value/time pair: %v %v", headers, times)
		}
	}
	writers.Wait()
}

func TestWithFreshResponseHeadersHolderIsolatesAttempts(t *testing.T) {
	requestCtx := WithResponseHeadersHolder(context.Background())
	SetResponseHeaders(requestCtx, http.Header{"X-Upstream-Attempt": []string{"request"}})

	firstAttemptCtx := WithFreshResponseHeadersHolder(requestCtx)
	if headers := GetResponseHeaders(firstAttemptCtx); len(headers) != 0 {
		t.Fatalf("fresh attempt inherited request headers: %#v", headers)
	}
	SetResponseHeaders(firstAttemptCtx, http.Header{"X-Upstream-Attempt": []string{"first"}})

	secondAttemptCtx := WithFreshResponseHeadersHolder(firstAttemptCtx)
	if headers := GetResponseHeaders(secondAttemptCtx); len(headers) != 0 {
		t.Fatalf("second attempt inherited first attempt headers: %#v", headers)
	}
	SetResponseHeaders(secondAttemptCtx, http.Header{"X-Upstream-Attempt": []string{"second"}})

	if got := GetResponseHeaders(requestCtx).Get("X-Upstream-Attempt"); got != "request" {
		t.Fatalf("request holder = %q, want request", got)
	}
	if got := GetResponseHeaders(firstAttemptCtx).Get("X-Upstream-Attempt"); got != "first" {
		t.Fatalf("first attempt holder = %q, want first", got)
	}
	if got := GetResponseHeaders(secondAttemptCtx).Get("X-Upstream-Attempt"); got != "second" {
		t.Fatalf("second attempt holder = %q, want second", got)
	}
	fresh := WithFreshResponseHeadersHolder(secondAttemptCtx)
	if headers, times := GetResponseHeadersObservation(fresh); len(headers) != 0 || len(times) != 0 {
		t.Fatalf("fresh attempt inherited acquisition: %v %v", headers, times)
	}
}
