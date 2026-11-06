package usage

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

type recordProvenancePluginFunc func(context.Context, Record)

func (fn recordProvenancePluginFunc) HandleUsage(ctx context.Context, record Record) {
	fn(ctx, record)
}

// The queue and each consumer own their snapshots, even when the caller,
// synchronous observer, or an earlier plugin mutates its copy before drain.
func TestManagerPublishClonesResponseObservation(t *testing.T) {
	mgr := NewManager(1)
	defer mgr.Stop()
	entered := make(chan struct{})
	release := make(chan struct{}, 1)
	defer close(release)
	captured := &captureUsagePlugin{records: make(chan Record, 1)}
	initialAt := time.Date(2026, 4, 25, 0, 1, 0, 123456789, time.UTC)
	primaryAt := initialAt.Add(time.Minute)
	laterAt := primaryAt.Add(time.Hour)

	mgr.Register(recordProvenancePluginFunc(func(_ context.Context, record Record) {
		close(entered)
		<-release
		record.ResponseHeaders["X-Codex-Primary-Used-Percent"][0] = "plugin-mutation"
		record.ResponseHeadersObservedAt["X-Codex-Primary-Used-Percent"] = laterAt
	}))
	mgr.Register(captured)

	var observed Record
	ctx := WithObserver(context.Background(), func(record Record) {
		observed = record
		record.ResponseHeaders["X-Codex-Secondary-Used-Percent"][0] = "observer-mutation"
		record.ResponseHeadersObservedAt["X-Codex-Secondary-Used-Percent"] = laterAt
	})
	source := Record{
		RequestID: "execution-1", TraceID: "trace-1", Provider: "codex", Model: "model-1",
		AuthID: "auth-1", AuthIndex: "index-1", ResponseModel: "served-model-1",
		RequestedAt: initialAt.Add(-time.Minute), Latency: 3 * time.Second, TTFT: 42 * time.Millisecond,
		ResponseHeaders: http.Header{
			"X-Codex-Primary-Used-Percent":   {"11", "12"},
			"X-Codex-Secondary-Used-Percent": {"20"},
		},
		ResponseHeadersObservedAt: map[string]time.Time{
			"X-Codex-Primary-Used-Percent":   primaryAt,
			"X-Codex-Secondary-Used-Percent": initialAt,
		},
	}
	mgr.Publish(ctx, source)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher did not reach publication gate")
	}
	if source.ResponseHeaders.Get("X-Codex-Secondary-Used-Percent") != "20" || !source.ResponseHeadersObservedAt["X-Codex-Secondary-Used-Percent"].Equal(initialAt) {
		t.Fatal("synchronous observer mutated the caller's observation")
	}

	source.ResponseHeaders["X-Codex-Primary-Used-Percent"][0] = "caller-mutation"
	source.ResponseHeadersObservedAt["X-Codex-Primary-Used-Percent"] = laterAt
	observed.ResponseHeaders["X-Codex-Primary-Used-Percent"][1] = "retained-observer-mutation"
	observed.ResponseHeadersObservedAt["X-Codex-Primary-Used-Percent"] = laterAt
	release <- struct{}{}

	select {
	case record := <-captured.records:
		primary := record.ResponseHeaders.Values("X-Codex-Primary-Used-Percent")
		if len(primary) != 2 || primary[0] != "11" || primary[1] != "12" || record.ResponseHeaders.Get("X-Codex-Secondary-Used-Percent") != "20" {
			t.Fatalf("queued header values changed: %v", record.ResponseHeaders)
		}
		if len(record.ResponseHeadersObservedAt) != 2 || !record.ResponseHeadersObservedAt["X-Codex-Primary-Used-Percent"].Equal(primaryAt) || !record.ResponseHeadersObservedAt["X-Codex-Secondary-Used-Percent"].Equal(initialAt) {
			t.Fatalf("queued acquisitions changed: %v", record.ResponseHeadersObservedAt)
		}
		if record.RequestID != source.RequestID || record.TraceID != source.TraceID || record.Provider != source.Provider || record.Model != source.Model || record.AuthID != source.AuthID || record.AuthIndex != source.AuthIndex || record.ResponseModel != source.ResponseModel {
			t.Fatalf("request attribution changed: %+v", record)
		}
		if !record.RequestedAt.Equal(source.RequestedAt) || record.Latency != source.Latency || record.TTFT != source.TTFT {
			t.Fatalf("request timing changed: requested_at=%v latency=%v ttft=%v", record.RequestedAt, record.Latency, record.TTFT)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("queued observation was not delivered")
	}
}

func TestManagerPublishDoesNotInventResponseAcquisition(t *testing.T) {
	for _, tc := range []struct {
		name       string
		observedAt map[string]time.Time
	}{
		{name: "legacy absent"},
		{name: "explicit unknown", observedAt: map[string]time.Time{"Retry-After": {}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := NewManager(1)
			defer mgr.Stop()
			captured := &captureUsagePlugin{records: make(chan Record, 1)}
			mgr.Register(captured)
			ctx := logging.WithFreshResponseHeadersHolder(context.Background())
			logging.SetResponseHeadersAt(ctx, http.Header{"Retry-After": {"999"}}, time.Date(2026, 4, 25, 0, 1, 0, 0, time.UTC))
			mgr.Publish(ctx, Record{
				RequestedAt:               time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC),
				ResponseHeaders:           http.Header{"Retry-After": {"30"}},
				ResponseHeadersObservedAt: tc.observedAt,
			})
			select {
			case record := <-captured.records:
				if record.ResponseHeaders.Get("Retry-After") != "30" {
					t.Fatalf("record headers were replaced from context: %v", record.ResponseHeaders)
				}
				if tc.observedAt == nil {
					if record.ResponseHeadersObservedAt != nil {
						t.Fatalf("legacy acquisition was invented: %v", record.ResponseHeadersObservedAt)
					}
				} else if len(record.ResponseHeadersObservedAt) != 1 || !record.ResponseHeadersObservedAt["Retry-After"].IsZero() {
					t.Fatalf("unknown acquisition was replaced: %v", record.ResponseHeadersObservedAt)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("legacy record was not delivered")
			}
		})
	}
}
