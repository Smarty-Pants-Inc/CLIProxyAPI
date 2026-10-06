package openai

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// Real handler, real executor, controlled HTTP upstream: no provider spend.
func TestImagesMultipartCompactionRound2RealHandlerAdmission(t *testing.T) {
	for _, stream := range []bool{false, true} {
		name := "nonstream"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			const model = "round2-compat-image"
			const compatName = "round2-compat"
			providerKey := util.OpenAICompatibleProviderKey(compatName)
			var executions atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				executions.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/images/edits" {
					t.Errorf("upstream request = %s %q", r.Method, r.URL.Path)
				}
				if r.Header.Get("User-Agent") != "cli-proxy-openai-compat" {
					t.Errorf("upstream executor attribution = %q", r.Header.Get("User-Agent"))
				}
				if stream && r.Header.Get("Accept") != "text/event-stream" {
					t.Errorf("upstream stream Accept = %q", r.Header.Get("Accept"))
				}
				if r.Header.Get("Authorization") != "Bearer round2-key" {
					t.Errorf("upstream account attribution = %q", r.Header.Get("Authorization"))
				}
				if err := r.ParseMultipartForm(1 << 20); err != nil {
					t.Errorf("upstream multipart parse: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				defer r.MultipartForm.RemoveAll()
				if r.FormValue("model") != model {
					t.Errorf("upstream model = %q, want %q", r.FormValue("model"), model)
				}
				wantStream := ""
				if stream {
					wantStream = "true"
				}
				if r.FormValue("stream") != wantStream {
					t.Errorf("upstream stream = %q, want %q", r.FormValue("stream"), wantStream)
				}
				file, _, err := r.FormFile("image")
				if err != nil {
					t.Errorf("upstream missing image: %v", err)
					return
				}
				data, err := io.ReadAll(file)
				_ = file.Close()
				if err != nil || string(data) != "round2-image-bytes" || r.FormValue("prompt") != "edit this" {
					t.Errorf("upstream body changed: image=%q prompt=%q err=%v", data, r.FormValue("prompt"), err)
				}
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, "event: image_edit.completed\ndata: {\"type\":\"image_edit.completed\",\"b64_json\":\"cm91bmQy\"}\n\n")
				} else {
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"created":1,"data":[{"b64_json":"cm91bmQy"}]}`)
				}
			}))
			defer upstream.Close()
			origin := coreauth.NewSessionAffinitySelector(&coreauth.FillFirstSelector{})
			defer origin.Stop()
			manager := coreauth.NewManager(nil, origin, nil)
			manager.SetRetryConfig(0, 0, 0)
			cfg := &internalconfig.Config{
				OpenAICompatibility: []internalconfig.OpenAICompatibility{{
					Name:          compatName,
					BaseURL:       upstream.URL,
					APIKeyEntries: []internalconfig.OpenAICompatibilityAPIKey{{APIKey: "round2-key"}},
					Models:        []internalconfig.OpenAICompatibilityModel{{Name: model, Alias: model, Image: true}},
				}},
			}
			manager.SetConfig(cfg)
			// Named compat auths select by the namespaced key, not the generic provider.
			manager.RegisterExecutor(runtimeexecutor.NewOpenAICompatExecutor(providerKey, cfg))
			id := "round2-images-" + name
			if _, err := manager.Register(context.Background(), &coreauth.Auth{
				ID: id, Provider: providerKey, Label: compatName, Status: coreauth.StatusActive,
				Attributes: map[string]string{
					"base_url":                    upstream.URL,
					"api_key":                     "round2-key",
					"compat_name":                 compatName,
					"provider_key":                providerKey,
					coreauth.AttributeSource:      "config:round2-compat[round2]",
					coreauth.AttributeConfigIndex: "0",
				},
			}); err != nil {
				t.Fatal(err)
			}
			registry.GetGlobalRegistry().RegisterClient(id, providerKey, []*registry.ModelInfo{{ID: model, Object: "model", OwnedBy: compatName, Type: registry.OpenAIImageModelType}})
			defer registry.GetGlobalRegistry().UnregisterClient(id)
			handler := NewOpenAIAPIHandler(handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, manager))
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for key, value := range map[string]string{"model": model, "prompt": "edit this", "stream": nameToRound2Stream(stream)} {
				if err := writer.WriteField(key, value); err != nil {
					t.Fatal(err)
				}
			}
			part, err := writer.CreateFormFile("image", "image.png")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(part, "round2-image-bytes"); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			resp := performImagesEndpointRequest(t, "/v1/images/edits", writer.FormDataContentType(), &body, handler.ImagesEdits)
			if resp.Code != http.StatusOK || executions.Load() != 1 || !strings.Contains(resp.Body.String(), "cm91bmQy") {
				t.Fatalf("status=%d upstream executions=%d body=%s", resp.Code, executions.Load(), resp.Body.String())
			}
		})
	}
}

func nameToRound2Stream(stream bool) string {
	if stream {
		return "true"
	}
	return "false"
}
