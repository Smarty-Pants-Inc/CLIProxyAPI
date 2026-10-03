package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestCodexEmptyTranslatedStreamAfterServerToolIsNonReplayable(t *testing.T) {
	const model = "gpt-5.4"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":%q}}\n\n", model)
		_, _ = fmt.Fprint(w, "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"id\":\"search\",\"type\":\"web_search_call\",\"status\":\"in_progress\"}}\n\n")
	}))
	defer server.Close()
	exec := NewCodexExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{ID: "empty-server-tool", Provider: "codex", Attributes: map[string]string{"base_url": server.URL, "api_key": "test"}}
	payload := []byte(`{"model":"gpt-5.4","input":"hello"}`)
	result, err := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{Model: model, Payload: payload}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse, ResponseFormat: sdktranslator.FormatOpenAI, Stream: true, OriginalRequest: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	var terminalErr error
	payloadCount := 0
	for chunk := range result.Chunks {
		if len(chunk.Payload) != 0 {
			payloadCount++
		}
		if chunk.Err != nil {
			terminalErr = chunk.Err
		}
	}
	if payloadCount != 0 {
		t.Fatalf("fixture emitted %d translated payloads; it must exercise empty output", payloadCount)
	}
	var nonReplayable interface{ IsRequestStop() bool }
	if terminalErr == nil || !errors.As(terminalErr, &nonReplayable) || !nonReplayable.IsRequestStop() {
		t.Fatalf("server-side work was silently converted to replayable EOF: %T %v", terminalErr, terminalErr)
	}
}
