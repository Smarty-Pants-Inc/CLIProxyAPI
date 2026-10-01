package usage

import (
	"context"
	"testing"
)

func TestAPIKeyPolicyUsageObserverIsSynchronousAndPreserved(t *testing.T) {
	manager := NewManager(0)
	t.Cleanup(manager.Stop)
	calls := 0
	source, cancel := context.WithCancel(context.Background())
	source = WithRecordObserver(source, func(record Record) {
		calls++
		if record.APIKey != "synthetic-usage-owner" || record.Detail.InputTokens != 3 || record.Detail.OutputTokens != 2 {
			t.Fatal("usage record changed before accounting")
		}
	})
	cancel()
	ctx := WithRecordObserverFromContext(context.Background(), source)
	manager.Publish(ctx, Record{APIKey: "synthetic-usage-owner", Detail: Detail{InputTokens: 3, OutputTokens: 2}})
	if calls != 1 {
		t.Fatal("accounting waited for async plugin delivery")
	}
	manager.Publish(context.Background(), Record{})
	if calls != 1 {
		t.Fatal("observer escaped its request context")
	}
}
