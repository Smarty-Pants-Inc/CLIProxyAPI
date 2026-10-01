package pluginhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestAPIKeyPolicyPluginCredentialCallbacks(t *testing.T) {
	const key = "synthetic-callback-policy-client"
	digest := sha256.Sum256([]byte(key))
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}}}})
	file := filepath.Join(t.TempDir(), "denied.json")
	if err := os.WriteFile(file, []byte(`{"type":"claude","email":"denied@example.com","access_token":"synthetic-only","api_key":"synthetic-denied-provider-key"}`), 0600); err != nil {
		t.Fatal(err)
	}
	selected, err := manager.Register(context.Background(), &coreauth.Auth{ID: "callback-denied", Provider: "claude", FileName: "denied.json", Attributes: map[string]string{"path": file, "source": file, "api_key": "synthetic-denied-provider-key"}, Metadata: map[string]any{"email": "denied@example.com", "access_token": "synthetic-only", "api_key": "synthetic-denied-provider-key"}})
	if err != nil {
		t.Fatal(err)
	}
	host := New()
	host.SetAuthManager(manager)
	request, err := json.Marshal(pluginapi.HostAuthGetRequest{AuthIndex: selected.EnsureIndex()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := coreauth.WithClientAPIKeyPolicies(context.Background(), key, []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"verified.json"}}})
	instance := &hostCallbackInstance{}
	nativeCtx := withHostCallbackIdentity(context.Background(), "policy-plugin", instance)
	callbackID, release := host.openCallbackContextForPluginInstance(ctx, "policy-plugin", instance)
	nativeRequest, err := json.Marshal(pluginapi.HostAuthGetRequest{AuthIndex: selected.EnsureIndex(), HostCallbackID: callbackID})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{pluginabi.MethodHostAuthGet, pluginabi.MethodHostAuthGetRuntime} {
		if _, err := host.callFromPlugin(nativeCtx, method, request); err == nil {
			t.Fatal("native callback dropped request identity")
		}
		if _, err := host.callFromPlugin(nativeCtx, method, nativeRequest); err == nil {
			t.Fatal("native callback returned denied credential")
		}
		if _, err := host.callFromPlugin(withHostCallbackIdentity(context.Background(), "other-plugin", instance), method, nativeRequest); err == nil {
			t.Fatal("foreign callback ID accepted")
		}
	}
	for _, method := range []string{pluginabi.MethodHostModelExecute, pluginabi.MethodHostModelExecuteStream} {
		if _, err := host.callFromPlugin(nativeCtx, method, []byte(`{}`)); err == nil {
			t.Fatal("native model callback dropped principal")
		}
	}
	listRequest, _ := json.Marshal(map[string]string{"host_callback_id": callbackID})
	listed, err := host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthList, listRequest)
	if err != nil {
		t.Fatal(err)
	}
	var entries rpcHostAuthListResponse
	if err := json.Unmarshal(listed, &entries); err != nil || len(entries.Files) != 0 {
		t.Fatal("native list exposed denied credentials")
	}
	manager.SetConfig(&config.Config{})
	listed, err = host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthList, listRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(listed, &entries); err != nil || len(entries.Files) != 0 {
		t.Fatal("policy removal reopened native list")
	}
	if _, err := host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthGetRuntime, request); err == nil {
		t.Fatal("policy removal reopened identity-less native callback")
	}
	if _, err := host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthGetRuntime, nativeRequest); err == nil {
		t.Fatal("policy removal discarded restricted invocation floor")
	}
	release()
	if _, err := host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthGetRuntime, nativeRequest); err == nil {
		t.Fatal("expired callback ID accepted")
	}
	unrestrictedID, releaseUnrestricted := host.openCallbackContextForPluginInstance(coreauth.WithClientAPIKey(context.Background(), "unpolicied-key"), "policy-plugin", instance)
	defer releaseUnrestricted()
	unrestrictedRequest, _ := json.Marshal(pluginapi.HostAuthGetRequest{AuthIndex: selected.EnsureIndex(), HostCallbackID: unrestrictedID})
	if _, err := host.callFromPlugin(nativeCtx, pluginabi.MethodHostAuthGetRuntime, unrestrictedRequest); err != nil {
		t.Fatalf("unpolicied native callback changed: %v", err)
	}
	if body, err := host.callHostAuthGet(ctx, request); err == nil || body != nil {
		t.Fatal("denied physical credential exposed to plugin")
	}
	if body, err := host.callHostAuthGetRuntime(ctx, request); err == nil || body != nil {
		t.Fatal("denied runtime credential exposed to plugin")
	}
	if body, err := host.callHostAuthSave(ctx, []byte(`{}`)); err == nil || body != nil {
		t.Fatal("restricted request could write credentials")
	}
	if body, err := host.callHostAuthGet(coreauth.WithClientAPIKey(context.Background(), "unpolicied-key"), request); err != nil || len(body) == 0 {
		t.Fatalf("unpolicied callback changed: %v", err)
	}
}
