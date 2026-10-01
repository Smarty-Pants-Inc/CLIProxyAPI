package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestAPIKeyPolicyWebsocketControlErrorDoesNotRetry(t *testing.T) {
	for _, refused := range []*coreauth.Error{
		{Code: "api_key_model_forbidden", HTTPStatus: 403},
		{Code: "api_key_daily_token_cap", HTTPStatus: 429},
	} {
		ctx := coreexecutor.WithWebsocketRequestCheck(context.Background(), func(string) error { return refused })
		if err := websocketPolicyCheck(ctx, "synthetic-auth")(); err != refused {
			t.Fatal("websocket lost client policy status")
		}
		if shouldRetryCodexWebsocketSend(refused) {
			t.Fatal("client-local refusal triggered websocket reconnect/credential retry")
		}
	}
}

func TestAPIKeyPolicyWebsocketRevokedDuringHandshake(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			var permitted atomic.Bool
			permitted.Store(true)
			var forwarded atomic.Int32
			done := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(done)
				permitted.Store(false)
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, _, err := conn.ReadMessage(); err == nil {
					forwarded.Add(1)
				}
			}))
			defer server.Close()
			executor := NewCodexWebsocketsExecutor(&config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}})
			selected := &coreauth.Auth{ID: "handshake-policy", Provider: "codex", Attributes: map[string]string{"api_key": "synthetic-token", "base_url": server.URL}}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ctx = coreexecutor.WithWebsocketAuthCheck(ctx, func(string) bool { return permitted.Load() })
			request := coreexecutor.Request{Model: "gpt-5-codex", Payload: []byte(`{"model":"gpt-5-codex","input":[{"role":"user","content":"denied content"}]}`)}
			opts := coreexecutor.Options{SourceFormat: sdktranslator.FormatOpenAIResponse}
			var err error
			if stream {
				_, err = executor.ExecuteStream(ctx, selected, request, opts)
			} else {
				_, err = executor.Execute(ctx, selected, request, opts)
			}
			if err == nil {
				t.Fatal("post-handshake revocation accepted")
			}
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				t.Fatal("denied socket not closed")
			}
			if forwarded.Load() != 0 {
				t.Fatal("client content forwarded after handshake revoked policy")
			}
		})
	}
}

func TestAPIKeyPolicyWebsocketChunkRevocationDoesNotFlush(t *testing.T) {
	done := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, reader, err := conn.NextReader()
		if err != nil {
			done <- nil
			return
		}
		body, _ := io.ReadAll(reader)
		done <- body
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var checks int
	deny := errors.New("policy revoked during chunks")
	check := func() error {
		checks++
		if checks >= 3 {
			return deny
		}
		return nil
	}
	payload := append(bytes.Repeat([]byte("a"), codexWebsocketWriteChunkSize), []byte("REVOKED-CONTENT")...)
	session := &codexWebsocketSession{}
	if err := session.writeMessage(conn, websocket.TextMessage, payload, check); !errors.Is(err, deny) {
		t.Fatalf("policy error = %v", err)
	}
	select {
	case body := <-done:
		if bytes.Contains(body, []byte("REVOKED-CONTENT")) {
			t.Fatal("denied chunk flushed")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("denied writer left open")
	}
}

func TestAPIKeyPolicyRetainedSocketRequiresDialCredential(t *testing.T) {
	selected := &coreauth.Auth{ID: "same-id", Provider: "codex", FileName: "A.json", Metadata: map[string]any{"email": "A@example.com"}}
	headers := http.Header{"Authorization": []string{"Bearer synthetic-A"}}
	original := websocketCredentialFingerprint(selected, headers)
	session := &codexWebsocketSession{authID: selected.ID, wsURL: "ws://synthetic", credentialFingerprint: original}
	if !websocketSessionTargetMatches(session, selected.ID, session.wsURL, "", original) {
		t.Fatal("same credential stopped matching")
	}
	selected.FileName = "B.json"
	selected.Metadata["email"] = "B@example.com"
	headers.Set("Authorization", "Bearer synthetic-B")
	if websocketSessionTargetMatches(session, selected.ID, session.wsURL, "", websocketCredentialFingerprint(selected, headers)) {
		t.Fatal("same ID blessed socket authenticated as denied A")
	}
}
