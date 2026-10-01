package pluginhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func securityRequest(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func securityRestrictedContext() context.Context {
	digest := sha256.Sum256([]byte("synthetic-only"))
	return coreauth.WithClientAPIKeyPolicies(context.Background(), "synthetic-only", []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"allowed.json"}}})
}

func TestRound2F10RawHTTPRequiresAdmission(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostHTTPDo, pluginabi.MethodHostHTTPDoStream} {
		for _, kind := range []string{"missing", "expired", "foreign-plugin", "foreign-instance", "restricted", "restricted-operation", "restricted-after-policy-removal", "expired-operation", "restricted-after-policy-addition"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				var sends atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sends.Add(1); _, _ = w.Write([]byte("ok")) }))
				defer server.Close()
				host := New()
				manager := coreauth.NewManager(nil, nil, nil)
				manager.SetConfig(&config.Config{})
				host.SetAuthManager(manager)
				instance := &hostCallbackInstance{}
				native := withHostCallbackIdentity(context.Background(), "owner", instance)
				parent := context.Background()
				if kind == "restricted" || kind == "restricted-operation" || kind == "restricted-after-policy-removal" {
					parent = securityRestrictedContext()
				}
				callbackID, closeOwner := host.openCallbackContextForPluginInstance(parent, "owner", instance)
				defer closeOwner()
				req := rpcHostHTTPRequest{HostCallbackID: callbackID, URL: server.URL, Method: http.MethodGet}
				switch kind {
				case "missing":
					req.HostCallbackID = ""
				case "expired":
					closeOwner()
				case "foreign-plugin":
					native = withHostCallbackIdentity(context.Background(), "other", instance)
				case "foreign-instance":
					native = withHostCallbackIdentity(context.Background(), "owner", &hostCallbackInstance{})
				case "restricted-operation":
					operationID, err := host.openHostHTTPOperation(native, callbackID)
					if err != nil {
						t.Fatal(err)
					}
					req.OperationID = operationID
				case "restricted-after-policy-removal":
					manager.SetConfig(&config.Config{})
				case "expired-operation":
					operationID, err := host.openHostHTTPOperation(native, callbackID)
					if err != nil {
						t.Fatal(err)
					}
					req.OperationID = operationID
					closeOwner()
				case "restricted-after-policy-addition":
					// Admission was unrestricted, but policy changes must be revalidated at send.
					closeOwner()
					parent = coreauth.WithClientAPIKey(context.Background(), "synthetic-only")
					callbackID, closeNewOwner := host.openCallbackContextForPluginInstance(parent, "owner", instance)
					defer closeNewOwner()
					req.HostCallbackID = callbackID
					digest := sha256.Sum256([]byte("synthetic-only"))
					manager.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"allowed.json"}}}}})
				}
				if _, err := host.callFromPlugin(native, method, securityRequest(t, req)); err == nil {
					t.Error("raw send accepted without active unrestricted owning admission")
				}
				if sends.Load() != 0 {
					t.Errorf("sent %d upstream requests", sends.Load())
				}
			})
		}
	}
}

func TestRound2F12ModelStreamOwnership(t *testing.T) {
	for _, method := range []string{pluginabi.MethodHostModelStreamRead, pluginabi.MethodHostModelStreamClose} {
		for _, kind := range []string{"missing", "foreign-plugin", "foreign-instance", "sibling-request", "expired"} {
			t.Run(method+"/"+kind, func(t *testing.T) {
				host := New()
				instance := &hostCallbackInstance{}
				native := withHostCallbackIdentity(context.Background(), "owner", instance)
				ownerID, closeOwner := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
				defer closeOwner()
				siblingID, closeSibling := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
				defer closeSibling()
				chunks := make(chan handlers.ModelExecutionChunk, 1)
				chunks <- handlers.ModelExecutionChunk{Payload: []byte("owner secret")}
				streamCtx, cancel := context.WithCancel(context.Background())
				defer cancel()
				streamID := host.modelStreams.open(ownerID, chunks, cancel)
				defer host.modelStreams.close(streamID)
				callbackID := ownerID
				switch kind {
				case "missing":
					callbackID = ""
				case "foreign-plugin":
					native = withHostCallbackIdentity(context.Background(), "other", instance)
				case "foreign-instance":
					native = withHostCallbackIdentity(context.Background(), "owner", &hostCallbackInstance{})
				case "sibling-request":
					callbackID = siblingID
				case "expired":
					closeOwner()
				}
				req := map[string]string{"stream_id": streamID, "host_callback_id": callbackID}
				if _, err := host.callFromPlugin(native, method, securityRequest(t, req)); err == nil {
					t.Error("non-owner model stream access accepted")
				}
				if streamCtx.Err() != nil {
					t.Error("unauthorized close canceled owner's stream")
				}
				if len(chunks) != 1 {
					t.Error("unauthorized read consumed owner's payload")
				}
			})
		}
	}
}

func TestRound2F12BlockedReadStopsOnOwnerClose(t *testing.T) {
	host := New()
	instance := &hostCallbackInstance{}
	native, cancelReader := context.WithCancel(withHostCallbackIdentity(context.Background(), "owner", instance))
	defer cancelReader()
	ownerID, closeOwner := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
	defer closeOwner()
	chunks := make(chan handlers.ModelExecutionChunk)
	host.SetModelExecutor(&fakeHostModelExecutor{executeModelStream: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionStream, *interfaces.ErrorMessage) {
		return handlers.ModelExecutionStream{Chunks: chunks}, nil
	}})
	raw, err := host.callFromPlugin(native, pluginabi.MethodHostModelExecuteStream, securityRequest(t, rpcHostModelExecutionRequest{HostModelExecutionRequest: pluginapi.HostModelExecutionRequest{Stream: true}, HostCallbackID: ownerID}))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := decodeRPCEnvelope[pluginapi.HostModelStreamResponse](raw)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, errRead := host.callFromPlugin(native, pluginabi.MethodHostModelStreamRead, securityRequest(t, map[string]string{"stream_id": resp.StreamID, "host_callback_id": ownerID}))
		result <- errRead
	}()
	closeOwner()
	select {
	case errRead := <-result:
		if errRead == nil {
			t.Error("closed owner read accepted")
		}
	case <-time.After(time.Second):
		t.Error("owner close did not unblock read")
		cancelReader()
		<-result
	}
}

func TestRound2F13ModelStreamStartupCancellation(t *testing.T) {
	for _, kind := range []string{"parent-cancel", "owner-close", "instance-close", "expired-owner"} {
		t.Run(kind, func(t *testing.T) {
			host := New()
			instance := &hostCallbackInstance{}
			native := withHostCallbackIdentity(context.Background(), "owner", instance)
			parent, cancelParent := context.WithCancel(context.Background())
			defer cancelParent()
			ownerID, closeOwner := host.openCallbackContextForPluginInstance(parent, "owner", instance)
			defer closeOwner()
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			host.SetModelExecutor(&fakeHostModelExecutor{executeModelStream: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionStream, *interfaces.ErrorMessage) {
				entered <- ctx
				select {
				case <-ctx.Done():
				case <-release:
				}
				return handlers.ModelExecutionStream{Chunks: make(chan handlers.ModelExecutionChunk)}, nil
			}})
			if kind == "expired-owner" {
				closeOwner()
			}
			result := make(chan error, 1)
			go func() {
				_, err := host.callFromPlugin(native, pluginabi.MethodHostModelExecuteStream, securityRequest(t, rpcHostModelExecutionRequest{HostModelExecutionRequest: pluginapi.HostModelExecutionRequest{Stream: true}, HostCallbackID: ownerID}))
				result <- err
			}()
			select {
			case streamCtx := <-entered:
				if kind == "expired-owner" {
					t.Error("executor entered with expired owner")
				}
				switch kind {
				case "parent-cancel":
					cancelParent()
				case "owner-close":
					closeOwner()
				case "instance-close":
					host.closeHostHTTPCallbackInstance("owner", instance)
				}
				select {
				case <-streamCtx.Done():
				case <-time.After(time.Second):
					t.Error("startup did not preserve owner cancellation")
				}
				close(release)
				<-result
			case err := <-result:
				close(release)
				if kind != "expired-owner" || err == nil {
					t.Errorf("unexpected startup result: %v", err)
				}
			case <-time.After(2 * time.Second):
				close(release)
				cancelParent()
				<-result
				t.Fatal("startup did not enter executor or return")
			}
		})
	}
}

func TestRound2F14ScopedCapabilityAlwaysChecksOwner(t *testing.T) {
	for _, kind := range []string{"foreign-plugin", "foreign-instance", "expired"} {
		t.Run(kind, func(t *testing.T) {
			host := New()
			instance := &hostCallbackInstance{}
			native := withHostCallbackIdentity(context.Background(), "owner", instance)
			id, closeOwner := host.openCallbackContextForPluginInstance(context.Background(), "owner", instance)
			defer closeOwner()
			switch kind {
			case "foreign-plugin":
				native = withHostCallbackIdentity(context.Background(), "foreign", instance)
			case "foreign-instance":
				native = withHostCallbackIdentity(context.Background(), "owner", &hostCallbackInstance{})
			case "expired":
				closeOwner()
			}
			var calls atomic.Int32
			host.SetModelExecutor(&fakeHostModelExecutor{executeModel: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionResponse, *interfaces.ErrorMessage) {
				calls.Add(1)
				return handlers.ModelExecutionResponse{}, nil
			}})
			for _, method := range []string{pluginabi.MethodHostModelExecute, pluginabi.MethodHostAuthList} {
				if _, err := host.callFromPlugin(native, method, securityRequest(t, map[string]string{"host_callback_id": id})); err == nil {
					t.Errorf("%s accepted non-owner capability without configured policy", method)
				}
			}
			if calls.Load() != 0 {
				t.Error("non-owner entered model executor")
			}
		})
	}
}

func TestRound2F14CallbackCapabilitiesAndConcurrentAdmissions(t *testing.T) {
	host := New()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(&config.Config{})
	host.SetAuthManager(manager)
	instance := &hostCallbackInstance{}
	native := withHostCallbackIdentity(context.Background(), "same-plugin", instance)
	restricted := securityRestrictedContext()
	restrictedID, closeRestricted := host.openCallbackContextForPluginInstance(restricted, "same-plugin", instance)
	defer closeRestricted()
	unrestrictedInstance := &hostCallbackInstance{}
	unrestrictedID, closeUnrestricted := host.openCallbackContextForPluginInstance(context.Background(), "same-plugin", unrestrictedInstance)
	defer closeUnrestricted()
	for _, id := range []string{restrictedID, unrestrictedID} {
		if _, err := strconv.ParseUint(id, 10, 64); err == nil || len(id) < 26 {
			t.Errorf("callback handle is predictable, not an unguessable invocation capability: %q", id)
		}
	}
	if restrictedID == unrestrictedID {
		t.Fatal("capability reused")
	}
	// Separate native instances may execute concurrently with independent floors.
	// Round3 tests prove one instance never receives two live authorities.
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	host.SetModelExecutor(&fakeHostModelExecutor{executeModel: func(ctx context.Context, req handlers.ModelExecutionRequest) (handlers.ModelExecutionResponse, *interfaces.ErrorMessage) {
		entered <- struct{}{}
		<-release
		if manager.HasClientAPIKeyPolicy(ctx) != (req.Model == "restricted") {
			return handlers.ModelExecutionResponse{}, &interfaces.ErrorMessage{StatusCode: 500}
		}
		return handlers.ModelExecutionResponse{StatusCode: 200}, nil
	}})
	result := make(chan error, 2)
	for model, id := range map[string]string{"restricted": restrictedID, "unrestricted": unrestrictedID} {
		req := securityRequest(t, rpcHostModelExecutionRequest{HostModelExecutionRequest: pluginapi.HostModelExecutionRequest{Model: model}, HostCallbackID: id})
		caller := native
		if id == unrestrictedID {
			caller = withHostCallbackIdentity(context.Background(), "same-plugin", unrestrictedInstance)
		}
		go func() { _, err := host.callFromPlugin(caller, pluginabi.MethodHostModelExecute, req); result <- err }()
	}
	for range 2 {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Error("separate-instance executions did not overlap")
		}
	}
	close(release)
	for range 2 {
		if err := <-result; err != nil {
			t.Errorf("concurrent admission mismatch: %v", err)
		}
	}
}
