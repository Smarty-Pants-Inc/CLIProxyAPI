package pluginhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRound3F17PhysicalCredentialBinding(t *testing.T) {
	for _, change := range []string{"email", "token", "provider", "account", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			host := New()
			manager := coreauth.NewManager(nil, nil, nil)
			host.SetAuthManager(manager)
			const key = "synthetic-physical-policy-key"
			digest := sha256.Sum256([]byte(key))
			policies := []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"a@example.invalid"}}}
			manager.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: policies}})
			path := filepath.Join(t.TempDir(), "credential.json")
			metadata := map[string]any{"type": "codex", "email": "a@example.invalid", "access_token": "synthetic-token-a", "account_id": "account-a"}
			original, _ := json.Marshal(metadata)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			selected, err := host.buildAuthFromFileData(path, original)
			if err != nil {
				t.Fatal(err)
			}
			selected, err = manager.Register(context.Background(), selected)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "email":
				metadata["email"] = "b@example.invalid"
				metadata["access_token"] = "synthetic-token-b"
			case "token":
				metadata["access_token"] = "synthetic-token-b"
			case "provider":
				metadata["type"] = "xai"
			case "account":
				metadata["account_id"] = "account-b"
			}
			physical, _ := json.Marshal(metadata)
			if err = os.WriteFile(path, physical, 0600); err != nil {
				t.Fatal(err)
			}
			// No watcher publication: runtime still authorizes coherent A.
			owner := coreauth.WithClientAPIKeyPolicies(context.Background(), key, policies)
			instance := &hostCallbackInstance{}
			native := withHostCallbackIdentity(context.Background(), "physical-owner", instance)
			id, closeOwner := host.openCallbackContextForPluginInstance(owner, "physical-owner", instance)
			defer closeOwner()
			raw, err := host.callFromPlugin(native, pluginabi.MethodHostAuthGet, securityRequest(t, map[string]string{"auth_index": selected.EnsureIndex(), "host_callback_id": id}))
			if change == "unchanged" {
				if err != nil {
					t.Fatal(err)
				}
				response, e := decodeRPCEnvelope[rpcHostAuthGetResponse](raw)
				if e != nil || string(response.JSON) != string(physical) {
					t.Fatalf("unchanged physical credential not returned: %v", e)
				}
			} else if err == nil {
				t.Fatal("physical credential not bound to the authorized runtime identity/token")
			}
		})
	}
}

type round3NativeClient struct {
	instance *hostCallbackInstance
	entered  chan string
	release  chan struct{}
	calls    atomic.Int32
}

func (c *round3NativeClient) callbackInstance() *hostCallbackInstance { return c.instance }
func (c *round3NativeClient) Call(ctx context.Context, method string, request []byte) ([]byte, error) {
	c.calls.Add(1)
	c.entered <- method
	if method == pluginabi.MethodExecutorExecute {
		<-c.release
	}
	return marshalRPCResult(pluginapi.ExecutorResponse{})
}
func (*round3NativeClient) Shutdown() {}

func TestRound3F16DetachedStreamIsolation(t *testing.T) {
	host := New()
	inner := &round3NativeClient{instance: &hostCallbackInstance{}, entered: make(chan string, 3), release: make(chan struct{})}
	guarded := newGuardedPluginClient(inner)
	defer guarded.Shutdown()
	adapter := &rpcPluginAdapter{id: "same-native", host: host, client: guarded, instance: guarded.callbackInstance()}
	owner, cancel := context.WithCancel(securityRestrictedContext())
	defer cancel()
	stream, err := adapter.ExecuteStream(owner, pluginapi.ExecutorRequest{Model: "first"})
	if err != nil {
		t.Fatal(err)
	}
	other := coreauth.WithClientAPIKey(context.Background(), "synthetic-other-key")
	if _, err := adapter.CountTokens(other, pluginapi.ExecutorRequest{Model: "second"}); err == nil || inner.calls.Load() != 1 {
		t.Error("detached stream's live authority did not exclude another native invocation")
	}
	cancel()
	select {
	case _, ok := <-stream.Chunks:
		if ok {
			t.Fatal("canceled synthetic stream emitted data")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled stream did not clean up its invocation lease")
	}
	if _, err := adapter.CountTokens(other, pluginapi.ExecutorRequest{Model: "second"}); err != nil {
		t.Fatalf("closed stream prevents later isolated request: %v", err)
	}
}

func TestRound3F16NativeInvocationIsolation(t *testing.T) {
	for _, second := range []string{"scoped", "unscoped", "after-cancel"} {
		t.Run(second, func(t *testing.T) {
			host := New()
			inner := &round3NativeClient{instance: &hostCallbackInstance{}, entered: make(chan string, 3), release: make(chan struct{})}
			guarded := newGuardedPluginClient(inner)
			defer guarded.Shutdown()
			adapter := &rpcPluginAdapter{id: "same-native", host: host, client: guarded, instance: guarded.callbackInstance()}
			owner, cancel := context.WithCancel(securityRestrictedContext())
			defer cancel()
			first := make(chan error, 1)
			go func() {
				_, err := adapter.Execute(owner, pluginapi.ExecutorRequest{Model: "first", Payload: []byte("private first")})
				first <- err
			}()
			select {
			case <-inner.entered:
			case <-time.After(time.Second):
				close(inner.release)
				t.Fatal("first invocation did not enter")
			}
			if second == "after-cancel" {
				cancel()
				<-first
			}
			other := coreauth.WithClientAPIKey(context.Background(), "synthetic-other-key")
			var err error
			if second == "unscoped" {
				_, err = adapter.NormalizeRequest(other, pluginapi.RequestTransformRequest{})
			} else {
				_, err = adapter.CountTokens(other, pluginapi.ExecutorRequest{Model: "second", Payload: []byte("private second")})
			}
			if err == nil {
				t.Error("incompatible request entered an instance with live first authority")
			}
			if inner.calls.Load() != 1 {
				t.Errorf("native code received %d invocations, want only first", inner.calls.Load())
			}
			close(inner.release)
			if second != "after-cancel" {
				if err := <-first; err != nil {
					t.Fatal(err)
				}
			}
			// Wait for actual native return, not merely the canceled observer receipt.
			deadline := time.Now().Add(time.Second)
			for {
				id, closeScope := host.openCallbackContextForPluginInstance(other, "same-native", adapter.instance)
				closeScope()
				if id != "" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("native lease not released")
				}
				time.Sleep(time.Millisecond)
			}
			if _, err := adapter.CountTokens(other, pluginapi.ExecutorRequest{Model: "second"}); err != nil {
				t.Fatalf("completed first invocation prevents later isolated request: %v", err)
			}
		})
	}
}
