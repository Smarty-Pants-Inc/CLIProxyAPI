package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// F32: a policied zstd body that decodes past the 16 MiB request bound is
// rejected while decoding, before model checks, admission or any upstream send.
func TestF32PolicyCompressedBodyDecodedBound(t *testing.T) {
	big := []byte(`{"model":"MODEL","input":"` + strings.Repeat("a", 17<<20) + `"}`)
	enc, _ := zstd.NewWriter(nil)
	for _, tc := range []struct {
		name, model string
		cap         int64
	}{
		{name: "zero cap", model: "gpt-6.1-sol"},
		{name: "model denied", model: "other", cap: 10},
		{name: "allowed", model: "gpt-6.1-sol", cap: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
			defer upstream.Close()
			digest := sha256.Sum256([]byte("test-key"))
			models := []string{"gpt-6.1-sol"}
			cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"test-key"}, APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{"A"}, AllowedModels: &models, DailyRequestCap: &tc.cap}}}, WebsocketAuth: true}
			server := newTestServerWithConfig(t, cfg)
			server.handlers.AuthManager.RegisterExecutor(executor.NewCodexExecutor(cfg))
			a := &auth.Auth{ID: "A", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"api_key": "verified-A", "base_url": upstream.URL}}
			if _, err := server.handlers.AuthManager.Register(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient("A", "codex", []*registry.ModelInfo{{ID: "gpt-6.1-sol"}})
			defer registry.GetGlobalRegistry().UnregisterClient("A")
			body := enc.EncodeAll(bytes.Replace(big, []byte("MODEL"), []byte(tc.model), 1), nil)
			if len(body) >= 16<<20 {
				t.Fatalf("encoded body %d bytes is not under the encoded bound", len(body))
			}
			req := httptest.NewRequest("POST", "/v1/responses", bytes.NewReader(body))
			req.Header.Set("Content-Encoding", "zstd")
			req.Header.Set("Authorization", "Bearer test-key")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid policy request body") {
				t.Fatalf("decoded-oversize body: status=%d body=%s, want 400 invalid policy request body", rr.Code, rr.Body.String())
			}
			if calls.Load() != 0 {
				t.Fatalf("upstream calls=%d want 0", calls.Load())
			}
		})
	}
}
