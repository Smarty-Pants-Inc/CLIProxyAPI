package pluginhost

import (
	"context"
	"errors"
	"testing"
)

func TestPluginDeleteCanceledDrainPreservesClient(t *testing.T) {
	inner := &blockingGuardPluginClient{started: make(chan struct{}), release: make(chan struct{})}
	guarded := newGuardedPluginClient(inner)
	h := New()
	h.loaded["alpha"] = &loadedPlugin{id: "alpha", client: guarded}
	callDone := make(chan struct{})
	go func() { defer close(callDone); _, _ = guarded.Call(context.Background(), "blocked", nil) }()
	<-inner.started
	defer func() { close(inner.release); <-callDone; h.ShutdownAll() }()
	if !h.BeginPluginDelete("alpha") {
		t.Fatal("could not begin deletion")
	}
	defer h.EndPluginDelete("alpha")
	if _, err := guarded.acquire(); err == nil {
		guarded.release()
		t.Fatal("call admitted through tombstone")
	}
	if h.BeginPluginDelete("alpha") {
		t.Fatal("concurrent deletion admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.UnloadPluginForDeleteContext(ctx, "alpha") }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled drain: %v", err)
	}
	if !h.PluginLoaded("alpha") || inner.shutdown.Load() != 0 {
		t.Fatal("canceled drain detached or shut down active client")
	}
	h.EndPluginDelete("alpha")
	if _, err := guarded.acquire(); err != nil {
		t.Fatalf("call gate not restored: %v", err)
	}
	guarded.release()
}

func TestPluginDeleteReservationCoversCommit(t *testing.T) {
	h := New()
	if !h.BeginPluginDelete("alpha") {
		t.Fatal("could not begin deletion")
	}
	defer h.EndPluginDelete("alpha")
	if err := h.UnloadPluginForDeleteContext(context.Background(), "alpha"); err != nil {
		t.Fatal(err)
	}
	if !h.PluginBusy("alpha") {
		t.Fatal("plugin-store file ownership lost before commit")
	}
	// A reload cannot resurrect the plugin between drain and file/config commit.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if h.lockApply(ctx) {
		h.unlockApply()
		t.Fatal("apply slot released before commit")
	}
	h.EndPluginDelete("alpha")
	if h.PluginBusy("alpha") {
		t.Fatal("tombstone not cleared after commit")
	}
	if !h.lockApply(context.Background()) {
		t.Fatal("apply slot not restored")
	}
	// Admission must be nonblocking when another reload owns the apply slot.
	if h.BeginPluginDelete("beta") {
		h.EndPluginDelete("beta")
		t.Fatal("deletion admitted during reload")
	}
	h.unlockApply()
	if h.PluginBusy("beta") {
		t.Fatal("rejected deletion changed state")
	}
}
