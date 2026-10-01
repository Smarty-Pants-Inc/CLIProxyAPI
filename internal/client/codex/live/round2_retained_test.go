package live

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type round2PrepareTrap struct {
	captureExecutor
	armed bool
	calls int
}

func (e *round2PrepareTrap) PrepareRequest(request *http.Request, selected *auth.Auth) error {
	if e.armed {
		e.calls++
		return errors.New("test trap: sideband preparation must not be reached")
	}
	return e.captureExecutor.PrepareRequest(request, selected)
}

func TestRound2RetainedCallRejectsReplacementBeforeDial(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, manager, cfg, _, selected := round2Policy(t, true)
	defer handler.Close()
	executor := &round2PrepareTrap{captureExecutor: captureExecutor{responseBody: io.NopCloser(strings.NewReader("v=0\r\no=upstream-answer\r\n"))}}
	manager.RegisterExecutor(executor)
	registerCredential(t, manager, selected)
	handler.mediaRelay = &fakeMediaRelay{
		upstreamOffer: "v=0\r\no=gateway-offer\r\n",
		session:       &fakeMediaSession{downstreamSDP: "v=0\r\no=downstream-answer\r\n"},
	}
	current := cfg
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("userApiKey", "synthetic-round2-key")
		c.Set("accessProvider", "test")
		c.Request = c.Request.WithContext(auth.WithClientAPIKeyPolicies(c.Request.Context(), "synthetic-round2-key", current.APIKeyPolicies))
	})
	router.POST("/v1/realtime/calls", handler.Handle)
	router.GET("/v1/realtime", handler.HandleSideband)
	request := httptest.NewRequest(http.MethodPost, "/v1/realtime/calls", strings.NewReader(multipartBody("round2", "v=0\r\no=client-offer\r\n", `{"model":"gpt-realtime"}`)))
	request.Header.Set("Content-Type", "multipart/form-data; boundary=round2")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("bootstrap = %d: %s", response.Code, response.Body.String())
	}

	// A new attaching request has no policy floor after policy removal. The
	// retained call must still reject a same-ID, different-identity credential.
	current = &config.Config{}
	manager.SetConfig(current)
	replacement := selected.Clone()
	replacement.Metadata["email"] = "replacement@example.com"
	registerCredential(t, manager, replacement)
	executor.armed = true
	request = httptest.NewRequest(http.MethodGet, "/v1/realtime?call_id=call-123", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if executor.calls != 0 {
		t.Fatalf("replacement reached sideband preparation (%d calls)", executor.calls)
	}
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "api_key_policy_unavailable") {
		t.Fatalf("replacement was not denied by original floor: %d %s", response.Code, response.Body.String())
	}
}

func TestRound2RetainedCallSendIntersectsAdmissions(t *testing.T) {
	for _, scenario := range []string{"removed-policy-replacement", "replacement-cannot-bless-original", "attaching-floor", "retained-model-floor"} {
		t.Run(scenario, func(t *testing.T) {
			handler, manager, cfg, admitted, original := round2Policy(t, true)
			defer handler.Close()
			bootstrap, cancel := context.WithCancel(admitted)
			session := liveSession{authID: original.ID, admittedAuth: original.Clone(), policyContext: livePolicyContext(bootstrap)}
			cancel()
			if session.policyContext.Err() != nil {
				t.Fatal("retained admission inherited bootstrap cancellation")
			}
			manager.SetConfig(&config.Config{})
			attach := manager.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", nil), "gpt-realtime")
			attach = context.WithValue(attach, liveModelInspectionContextKey{}, true)
			selected := original.Clone()
			payload := []byte(`{"type":"response.create","response":{"model":"gpt-realtime"}}`)
			switch scenario {
			case "removed-policy-replacement":
				selected.Metadata["email"] = "replacement@example.com"
			case "replacement-cannot-bless-original":
				// Current policy admits the new record, but not the credential
				// that created the retained media call.
				selected.Metadata["email"] = "replacement@example.com"
				current := cfg.CloneForRuntime()
				current.APIKeyPolicies[0].AllowedAuths = []string{"replacement@example.com"}
				manager.SetConfig(current)
				// Relax admission to isolate validation of immutable identity.
				floor := cfg.CloneForRuntime()
				floor.APIKeyPolicies[0].AllowedAuths = []string{"*@example.com"}
				session.policyContext = livePolicyContext(manager.WithClientRequest(auth.WithClientAPIKeyPolicies(admitted, "synthetic-round2-key", floor.APIKeyPolicies), "gpt-realtime"))
			case "attaching-floor":
				floor := cfg.CloneForRuntime()
				floor.APIKeyPolicies[0].AllowedAuths = []string{"replacement@example.com"}
				attach = context.WithValue(manager.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", floor.APIKeyPolicies), "gpt-realtime"), liveModelInspectionContextKey{}, true)
			case "retained-model-floor":
				payload = []byte(`{"type":"response.create","response":{"model":"forbidden-model"}}`)
			}
			connection, transport := round2Websocket(t, nil, nil)
			if policy := handler.retainedClientMessagePolicy(attach, selected, session); policy != nil {
				if err := policy(payload); err != nil {
					return
				}
			}
			err := writeCheckedWebsocketMessage(connection, websocket.TextMessage, bytes.NewReader(payload), func() error { return handler.validateRetainedLiveAuth(attach, selected, session) })
			if err == nil || transport.wire.Len() != 0 {
				t.Fatalf("retained admission escaped before send: error=%v bytes=%d", err, transport.wire.Len())
			}
		})
	}
}

func TestRound2RetainedCallRevokesDuringSend(t *testing.T) {
	handler, manager, cfg, admitted, selected := round2Policy(t, true)
	defer handler.Close()
	session := liveSession{authID: selected.ID, admittedAuth: selected.Clone(), policyContext: livePolicyContext(admitted)}
	manager.SetConfig(&config.Config{})
	attach := context.WithValue(manager.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", nil), "gpt-realtime"), liveModelInspectionContextKey{}, true)
	connection, transport := round2Websocket(t, nil, func() {
		revoked := cfg.CloneForRuntime()
		revoked.APIKeyPolicies[0].AllowedAuths = nil
		manager.SetConfig(revoked)
	})
	err := writeCheckedWebsocketMessage(connection, websocket.TextMessage, strings.NewReader(strings.Repeat("i", 1<<20)), func() error { return handler.validateRetainedLiveAuth(attach, selected, session) })
	if err == nil || transport.wire.Len() == 0 || transport.wire.Len() > 4096+32 {
		t.Fatalf("retained mid-send revocation failed: error=%v bytes=%d", err, transport.wire.Len())
	}
	round2AssertNoFinalFrame(t, transport.wire.Bytes())
}

func TestRound2RetainedCallCompatibleAfterPolicyRemoval(t *testing.T) {
	handler, manager, _, admitted, selected := round2Policy(t, true)
	defer handler.Close()
	session := liveSession{authID: selected.ID, admittedAuth: selected.Clone(), policyContext: livePolicyContext(admitted)}
	manager.SetConfig(&config.Config{})
	attach := context.WithValue(manager.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", nil), "gpt-realtime"), liveModelInspectionContextKey{}, false)
	payload := []byte(`{"type":"response.create","response":{"model":"gpt-realtime"}}`)
	policy := handler.retainedClientMessagePolicy(attach, selected, session)
	if policy == nil {
		t.Fatal("removing policy also removed retained model inspection")
	}
	if err := policy(payload); err != nil {
		t.Fatal(err)
	}
	connection, transport := round2Websocket(t, nil, nil)
	err := writeCheckedWebsocketMessage(connection, websocket.TextMessage, bytes.NewReader(payload), func() error { return handler.validateRetainedLiveAuth(attach, selected, session) })
	if err != nil || transport.wire.Len() == 0 || transport.wire.Bytes()[0]&0x80 == 0 {
		t.Fatalf("compatible retained send failed: error=%v bytes=%d", err, transport.wire.Len())
	}
}
