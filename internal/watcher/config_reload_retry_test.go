package watcher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

// Capture timers instead of sleeping through backoff. The real timer path is
// covered by the SDK's store-failure management rotation regression.
type configRetryClock struct {
	delays    []time.Duration
	callbacks []func()
	timers    []*time.Timer
}

func newConfigRetryFixture(t *testing.T) (*Watcher, *configRetryClock, func(int) []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	publish := func(retry int) []byte {
		data := []byte(fmt.Sprintf("auth-dir: %q\nplugins:\n  dir: %q\nrequest-retry: %d\n", dir, filepath.Join(dir, "plugins"), retry))
		if err := config.WriteConfigAtomic(path, data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	publish(1)
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(path, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.SetConfig(cfg)
	clock := &configRetryClock{}
	w.configRetryAfterFunc = func(delay time.Duration, callback func()) *time.Timer {
		clock.delays = append(clock.delays, delay)
		clock.callbacks = append(clock.callbacks, callback)
		timer := time.NewTimer(time.Hour)
		clock.timers = append(clock.timers, timer)
		return timer
	}
	t.Cleanup(func() {
		_ = w.Stop()
		for _, timer := range clock.timers {
			timer.Stop()
		}
	})
	return w, clock, publish
}

func TestWatcherConfigRetryRecoveryRecordsCapturedHash(t *testing.T) {
	w, clock, publish := newConfigRetryFixture(t)
	prior := append([]byte(nil), w.oldConfigYaml...)
	updated := publish(2)
	calls := 0
	succeed := false
	w.SetReloadResultCallback(func(cfg *config.Config) bool {
		calls++
		if cfg.RequestRetry != 2 {
			t.Fatalf("applied request-retry=%d, want captured 2", cfg.RequestRetry)
		}
		return succeed
	})
	w.ReloadConfigIfChanged()
	if w.lastConfigHash != "" || !bytes.Equal(w.oldConfigYaml, prior) {
		t.Fatal("failed apply recorded hash or advanced applied snapshot")
	}
	if !bytes.Equal(w.configRetrySource, updated) || len(clock.callbacks) != 1 {
		t.Fatal("failed revision did not schedule its captured bytes")
	}
	succeed = true
	clock.callbacks[0]()
	sum := sha256.Sum256(updated)
	if w.lastConfigHash != hex.EncodeToString(sum[:]) {
		t.Fatal("recovered revision's exact hash not recorded")
	}
	if w.configRetryTimer != nil || w.configRetrySource != nil {
		t.Fatal("successful apply retained retry state")
	}
	w.ReloadConfigIfChanged()
	if calls != 2 || len(clock.callbacks) != 1 {
		t.Fatalf("successful revision not skipped: calls=%d schedules=%d", calls, len(clock.callbacks))
	}
}

func TestWatcherConfigRetryBounded(t *testing.T) {
	w, clock, _ := newConfigRetryFixture(t)
	calls := 0
	w.SetReloadResultCallback(func(*config.Config) bool { calls++; return false })
	w.ReloadConfigIfChanged()
	for attempt := 0; attempt < 3; attempt++ {
		if len(clock.callbacks) != attempt+1 {
			t.Fatalf("retry %d not scheduled", attempt+1)
		}
		clock.callbacks[attempt]()
	}
	if calls != 4 || len(clock.callbacks) != 3 || w.configRetryTimer != nil || w.lastConfigHash != "" {
		t.Fatalf("retry budget not bounded: calls=%d schedules=%d", calls, len(clock.callbacks))
	}
	if !reflect.DeepEqual(clock.delays, []time.Duration{time.Second, 5 * time.Second, 30 * time.Second}) {
		t.Fatalf("backoff=%v", clock.delays)
	}
	// A duplicate filesystem event can attempt application, but cannot restart the budget.
	w.ReloadConfigIfChanged()
	if len(clock.callbacks) != 3 {
		t.Fatal("unchanged failed bytes replenished automatic retry budget")
	}
}

func TestWatcherConfigRetrySuperseded(t *testing.T) {
	for _, withEvent := range []bool{true, false} {
		t.Run(fmt.Sprintf("new-file-event=%t", withEvent), func(t *testing.T) {
			w, clock, publish := newConfigRetryFixture(t)
			var applied []int
			w.SetReloadResultCallback(func(cfg *config.Config) bool {
				applied = append(applied, cfg.RequestRetry)
				return cfg.RequestRetry == 3
			})
			publish(2)
			w.ReloadConfigIfChanged()
			latest := publish(3)
			if withEvent {
				w.ReloadConfigIfChanged()
			}
			// An expired callback may race with cancellation; it must not reinstall 2.
			clock.callbacks[0]()
			if !reflect.DeepEqual(applied, []int{2, 3}) {
				t.Fatalf("superseded revision was reapplied: %v", applied)
			}
			sum := sha256.Sum256(latest)
			if w.lastConfigHash != hex.EncodeToString(sum[:]) {
				t.Fatal("new revision not observed")
			}
		})
	}
}

func TestWatcherConfigRetryShutdownCancelsPending(t *testing.T) {
	for _, shutdown := range []string{"Stop", "context"} {
		t.Run(shutdown, func(t *testing.T) {
			w, clock, _ := newConfigRetryFixture(t)
			calls := 0
			w.SetReloadResultCallback(func(*config.Config) bool { calls++; return false })
			w.ReloadConfigIfChanged()
			if len(clock.callbacks) != 1 {
				t.Fatal("retry not pending")
			}
			if shutdown == "Stop" {
				if err := w.Stop(); err != nil {
					t.Fatal(err)
				}
			} else {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				// Run the actual event loop's cancellation cleanup synchronously.
				w.processEvents(ctx)
			}
			clock.callbacks[0]()
			if calls != 1 || w.configRetryTimer != nil || w.configRetrySource != nil {
				t.Fatal("shutdown allowed a pending retry to apply")
			}
		})
	}
}
