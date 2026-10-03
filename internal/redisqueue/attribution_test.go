package redisqueue_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/redisqueue"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

type attributionCallback struct {
	calls atomic.Int32
	done  chan struct{}
}

func (p *attributionCallback) HandleUsage(_ context.Context, r usage.Record) {
	if r.Provider == "attribution-completion" && p.done != nil {
		close(p.done)
		return
	}
	p.calls.Add(1)
}

type attributionBlocker struct{ entered, release chan struct{} }

func (p *attributionBlocker) HandleUsage(_ context.Context, r usage.Record) {
	if r.Provider == "attribution-barrier" {
		close(p.entered)
		<-p.release
	}
}

func TestRestrictedClientAttributionHTTPAndSSE(t *testing.T) {
	keys := []string{"r3-client-one-private", "r3-client-two-private"}
	model := "gpt-6.1-sol"
	models := []string{model}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: keys}, WebsocketAuth: true, CommercialMode: true, AuthDir: t.TempDir()}
	cfg.RemoteManagement.SecretKey = "test-management-only"
	cfg.UsageStatisticsEnabled = true
	hashes := make([]string, len(keys))
	for i, key := range keys {
		digest := sha256.Sum256([]byte(key))
		hashes[i] = hex.EncodeToString(digest[:])
		cfg.APIKeyPolicies = append(cfg.APIKeyPolicies, config.APIKeyPolicy{KeySHA256: hashes[i], AllowedAuths: []string{"attribution-auth"}, AllowedModels: &models})
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer shared-upstream" {
			t.Error("wrong upstream credential")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":%q}}\n\n", model)
		fmt.Fprintf(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":%q,\"output\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":3,\"total_tokens\":7}}}\n\n", model)
	}))
	defer upstream.Close()
	manager := auth.NewManager(nil, nil, nil)
	server := api.NewServer(cfg, manager, sdkaccess.NewManager(), filepath.Join(t.TempDir(), "config.yaml"))
	manager.RegisterExecutor(executor.NewCodexExecutor(cfg))
	if _, err := manager.Register(context.Background(), &auth.Auth{ID: "attribution-auth", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"base_url": upstream.URL}, Metadata: map[string]any{"access_token": "shared-upstream", "account_id": "account-shared", "email": "shared@example.com"}}); err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient("attribution-auth", "codex", []*registry.ModelInfo{{ID: model}})
	defer registry.GetGlobalRegistry().UnregisterClient("attribution-auth")
	wasEnabled, wasUsageEnabled := redisqueue.Enabled(), redisqueue.UsageStatisticsEnabled()
	redisqueue.SetEnabled(true)
	redisqueue.SetUsageStatisticsEnabled(true)
	t.Cleanup(func() {
		redisqueue.SetEnabled(false)
		redisqueue.SetEnabled(wasEnabled)
		redisqueue.SetUsageStatisticsEnabled(wasUsageEnabled)
	})
	blocker := &attributionBlocker{entered: make(chan struct{}), release: make(chan struct{})}
	usage.RegisterNamedPlugin(t.Name()+" barrier", blocker)
	released := false
	defer func() {
		if !released {
			close(blocker.release)
		}
		usage.RegisterNamedPlugin(t.Name()+" barrier", &attributionCallback{})
	}()
	usage.PublishRecord(context.Background(), usage.Record{Provider: "attribution-barrier"})
	select {
	case <-blocker.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatcher barrier not reached")
	}
	subscriber, unsubscribe := redisqueue.SubscribeUsage()
	defer unsubscribe()
	<-subscriber // support-refresh capability message
	for i, key := range keys {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, model, i == 1)))
		req.Header.Set("Authorization", "Bearer "+key)
		// A competing client header is not the authenticated principal.
		req.Header.Set("X-Api-Key", "untrusted-client-header")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("client %d status=%d body=%s", i, response.Code, response.Body.String())
		}
	}
	// Reload an unrelated setting and register an external callback while records are queued.
	next := cfg.CloneForRuntime()
	next.Debug = !cfg.Debug
	manager.SetConfig(next)
	server.UpdateClients(next)
	external := &attributionCallback{done: make(chan struct{})}
	usage.RegisterNamedPlugin(t.Name()+" external", external)
	defer usage.RegisterNamedPlugin(t.Name()+" external", &attributionCallback{})
	close(blocker.release)
	released = true
	payloads := make([]json.RawMessage, 0, 2)
	for len(payloads) < 2 {
		select {
		case payload := <-subscriber:
			var record map[string]any
			if err := json.Unmarshal(payload, &record); err != nil {
				t.Fatal(err)
			}
			if record["provider"] == "codex" {
				payloads = append(payloads, payload)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("native usage dispatch did not complete")
		}
	}
	if output := os.Getenv("R3_ATTRIBUTION_PAYLOADS"); output != "" {
		data, err := json.Marshal(payloads)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, payload := range payloads {
		for _, key := range append(keys, "untrusted-client-header") {
			if strings.Contains(string(payload), key) {
				t.Errorf("plaintext client identity in native payload")
			}
		}
		var record map[string]any
		if err := json.Unmarshal(payload, &record); err != nil {
			t.Fatal(err)
		}
		if record["api_key_hash"] != hashes[i] {
			t.Errorf("client %d native api_key_hash=%v want=%s", i, record["api_key_hash"], hashes[i])
		}
		if record["api_key"] != "[REDACTED]" {
			t.Errorf("api_key=%v, want redacted", record["api_key"])
		}
	}
	// An ordinary marker proves all earlier callbacks finished, not merely that
	// the native sink wrote its payload before a later callback could run.
	usage.PublishRecord(context.Background(), usage.Record{Provider: "attribution-completion"})
	select {
	case <-external.done:
	case <-time.After(5 * time.Second):
		t.Fatal("usage callback completion marker missing")
	}
	if got := external.calls.Load(); got != 0 {
		t.Fatalf("restricted external callbacks=%d want=0", got)
	}
}
