package usage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type attributionNativeSink struct{ records chan Record }

func (*attributionNativeSink) BuiltinUsageSink()                         {}
func (p *attributionNativeSink) HandleUsage(_ context.Context, r Record) { p.records <- r }

type attributionExternalSink struct {
	calls atomic.Int32
	done  chan struct{}
}

func (p *attributionExternalSink) HandleUsage(_ context.Context, r Record) {
	if r.Provider == "attribution-completion" {
		close(p.done)
		return
	}
	p.calls.Add(1)
}

func TestNativeOnlyUsageRetainsClientDigest(t *testing.T) {
	manager := NewManager(2)
	defer manager.Stop()
	native := &attributionNativeSink{records: make(chan Record, 2)}
	external := &attributionExternalSink{done: make(chan struct{})}
	manager.Register(native)
	manager.Register(external)
	keys := []string{"native-client-one", "native-client-two"}
	for _, key := range keys {
		manager.Publish(WithoutPlugins(context.Background()), Record{APIKey: key})
	}
	for _, key := range keys {
		select {
		case record := <-native.records:
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), key) {
				t.Error("plaintext client key reached native sink")
			}
			var fields map[string]any
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(key))
			if fields["APIKeySHA256"] != hex.EncodeToString(digest[:]) {
				t.Errorf("native digest=%v want=%s", fields["APIKeySHA256"], hex.EncodeToString(digest[:]))
			}
			if record.APIKey != "[REDACTED]" {
				t.Error("native APIKey is not redacted")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("native usage missing")
		}
	}
	manager.Publish(context.Background(), Record{Provider: "attribution-completion"})
	select {
	case <-external.done:
	case <-time.After(5 * time.Second):
		t.Fatal("usage callback completion marker missing")
	}
	if got := external.calls.Load(); got != 0 {
		t.Errorf("external callbacks=%d want=0", got)
	}
}
