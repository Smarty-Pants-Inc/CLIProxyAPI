package usage

import (
	"context"
	"testing"
	"time"
)

type syncBuiltinUsagePlugin struct{ captureUsagePlugin }

func (*syncBuiltinUsagePlugin) BuiltinUsageSink() {}

// Upstream context backfill must run before the fork's restricted accounting
// barrier, never restore a raw key after it, and never enable external sinks.
func TestManagerContextAuthBackfillPreservesRestrictedAccounting(t *testing.T) {
	mgr := NewManager(1)
	defer mgr.Stop()
	builtin := &syncBuiltinUsagePlugin{captureUsagePlugin{records: make(chan Record, 1)}}
	external := &captureUsagePlugin{records: make(chan Record, 1)}
	// Put the external sink first: receiving the native record proves the
	// external-sink decision has already run, without a scheduling assumption.
	mgr.Register(external)
	mgr.Register(builtin)

	ctx := WithAPIKey(context.Background(), "sync-client-key")
	ctx = WithAccessProvider(ctx, "config-inline")
	ctx = WithoutPlugins(ctx)
	var observed Record
	calls := 0
	ctx = WithObserver(ctx, func(record Record) {
		observed = record
		calls++
	})
	mgr.Publish(ctx, Record{Provider: "codex", Model: "sync-model"})
	if calls != 1 {
		t.Fatalf("observer calls = %d, want 1", calls)
	}
	check := func(record Record) {
		t.Helper()
		if record.APIKey != "[REDACTED]" || record.APIKeySHA256 != APIKeyDigest("sync-client-key") {
			t.Fatalf("restricted identity = (%q, %q)", record.APIKey, record.APIKeySHA256)
		}
		if !record.IsNativeKey || record.AccessProvider != "config-inline" {
			t.Fatalf("lost upstream access metadata: native=%t provider=%q", record.IsNativeKey, record.AccessProvider)
		}
	}
	check(observed)
	select {
	case record := <-builtin.records:
		check(record)
	case <-time.After(5 * time.Second):
		t.Fatal("native accounting was not delivered")
	}
	select {
	case <-external.records:
		t.Fatal("restricted usage reached an external plugin")
	default:
	}
}
