package pluginhost

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Done is evaluated only after the bridge has resolved the stream and reached its
// blocking select. This handshake avoids using sleeps to guess read ordering.
type observedModelReadContext struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedModelReadContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestModelStreamBridgeBlockedReadLifetime(t *testing.T) {
	for _, kind := range []string{"owner-close", "instance-close", "explicit-close", "reader-cancel"} {
		t.Run(kind, func(t *testing.T) {
			host := New()
			instance := &hostCallbackInstance{}
			ownerID, closeOwner := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
			defer closeOwner()
			ownerCtx, _, _, ok := host.lookupCallbackContext(ownerID)
			if !ok {
				t.Fatal("owner not open")
			}
			streamID := host.modelStreams.open(ownerID, make(chan handlers.ModelExecutionChunk), nil)
			defer host.modelStreams.close(streamID)
			if !host.addCallbackCleanup(ownerID, func() { host.modelStreams.close(streamID) }) {
				t.Fatal("cleanup not attached")
			}
			readCtx, cancelRead := context.WithCancel(ownerCtx)
			defer cancelRead()
			observed := &observedModelReadContext{Context: readCtx, entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() { _, _, err := host.modelStreams.read(observed, streamID, ownerID); done <- err }()
			select {
			case <-observed.entered:
			case <-time.After(time.Second):
				cancelRead()
				<-done
				t.Fatal("read did not enter blocking select")
			}
			switch kind {
			case "owner-close":
				closeOwner()
			case "instance-close":
				host.closeHostHTTPCallbackInstance("owner", instance)
			case "explicit-close":
				native := withHostCallbackIdentity(context.Background(), "owner", instance)
				_, err := host.callFromPlugin(native, pluginabi.MethodHostModelStreamClose, securityRequest(t, pluginapi.HostModelStreamCloseRequest{StreamID: streamID, HostCallbackID: ownerID}))
				if err != nil {
					t.Error(err)
					cancelRead()
				}
			case "reader-cancel":
				cancelRead()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Error("closed/canceled blocked read succeeded")
				}
			case <-time.After(time.Second):
				cancelRead()
				<-done
				t.Fatal("blocked read did not terminate")
			}
		})
	}
}

func TestCallbackScopeRejectsAlreadyCanceledOrClosedOwner(t *testing.T) {
	host := New()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	id, closeCanceled := host.openCallbackContext(canceled)
	defer closeCanceled()
	if id != "" {
		t.Error("opened already canceled callback")
	}
	instance := &hostCallbackInstance{}
	instance.closed.Store(true)
	id, closeClosed := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
	defer closeClosed()
	if id != "" {
		t.Error("opened already closed instance callback")
	}
}
