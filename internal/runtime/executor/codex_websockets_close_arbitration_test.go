package executor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/api/handlers/openai"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	execution "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// End is the real reader's teardown receipt, not a sleep or a guessed EOF delay.
// Holding the first observer event until End forces quota + EOF to precede
// classification through the real handler, named session and disconnect subscriber.
type arbitrationLifecycle struct {
	done chan struct{}
	once sync.Once
}

func (*arbitrationLifecycle) Bind(func() error) error { return nil }
func (l *arbitrationLifecycle) End(string)            { l.once.Do(func() { close(l.done) }) }

type arbitrationExecutor struct {
	*CodexWebsocketsExecutor
	t            *testing.T
	lifecycle    *arbitrationLifecycle
	decisionGate <-chan struct{}
	session      chan *codexWebsocketSession
}

func (e *arbitrationExecutor) ExecuteStream(ctx context.Context, a *auth.Auth, req execution.Request, opts execution.Options) (*execution.StreamResult, error) {
	if a.Attributes["api_key"] == "primary" {
		opts.ExecutionLifecycle = e.lifecycle
		original := opts.WebSocketResponseObserver
		var once sync.Once
		opts.WebSocketResponseObserver = func(ctx context.Context, event execution.WebSocketResponseEvent) {
			once.Do(func() {
				select {
				case <-e.lifecycle.done:
				case <-time.After(5 * time.Second):
					e.t.Error("reader did not tear down before classification")
				}
				id := executionSessionIDFromOptions(opts)
				e.store.mu.Lock()
				sess := e.store.sessions[id]
				e.store.mu.Unlock()
				if sess == nil || id == "" {
					e.t.Error("real handler did not use a named session")
				}
				if e.session != nil {
					e.session <- sess
				}
				if e.decisionGate != nil {
					select {
					case <-e.decisionGate:
					case <-ctx.Done():
					}
				}
			})
			if original != nil {
				original(ctx, event)
			}
		}
	}
	return e.CodexWebsocketsExecutor.ExecuteStream(ctx, a, req, opts)
}

func arbitrationClient(t *testing.T, refusal string, fallback bool, gate <-chan struct{}) (*websocket.Conn, *arbitrationExecutor, *atomic.Int32) {
	t.Helper()
	model := "arbitration-" + strings.ReplaceAll(t.Name(), "/", "-")
	explicitStatus := strings.HasPrefix(refusal, "explicit:")
	refusal = strings.TrimPrefix(refusal, "explicit:")
	attempts := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = c.Close() }()
		if _, _, err := c.ReadMessage(); err != nil {
			return
		}
		if r.Header.Get("Authorization") == "Bearer primary" {
			_ = c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.created","response":{"id":"primary","model":%q,"output":[]}}`, model)))
			terminal := fmt.Sprintf(`{"type":"response.failed","response":{"id":"primary","model":%q,"status":"failed","error":{"code":%q,"message":"original refusal"}}}`, model, refusal)
			if explicitStatus {
				terminal = fmt.Sprintf(`{"type":"error","status":429,"error":{"code":%q,"message":"original refusal"}}`, refusal)
			}
			_ = c.WriteMessage(websocket.TextMessage, []byte(terminal))
			return // quota followed immediately by EOF
		}
		attempts.Add(1)
		_ = c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"replacement","model":%q,"status":"completed","output":[]}}`, model)))
		// Keep the replacement upstream alive. A second downstream turn proves both
		// that the original client is usable and the hold was cancelled on retry.
		if _, _, err := c.ReadMessage(); err == nil {
			_ = c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":"next","model":%q,"status":"completed","output":[]}}`, model)))
		}
	}))
	t.Cleanup(upstream.Close)
	cfg := &config.Config{}
	exec := &arbitrationExecutor{CodexWebsocketsExecutor: NewCodexWebsocketsExecutor(cfg), t: t,
		lifecycle: &arbitrationLifecycle{done: make(chan struct{})}, decisionGate: gate, session: make(chan *codexWebsocketSession, 1)}
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	t.Cleanup(func() { exec.CloseExecutionSession(auth.CloseAllExecutionSessionsID) })
	manager := auth.NewManager(nil, &auth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(exec)
	tokens := []string{"primary"}
	if fallback {
		tokens = append(tokens, "secondary")
	}
	for i, token := range tokens {
		id := fmt.Sprintf("%s-%d", t.Name(), i)
		registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		_, err := manager.Register(context.Background(), &auth.Auth{ID: id, Provider: "codex", Status: auth.StatusActive,
			Attributes: map[string]string{"api_key": token, "base_url": upstream.URL, "websockets": "true"}, Metadata: map[string]any{"disable_cooling": false}})
		if err != nil {
			t.Fatal(err)
		}
	}
	h := openai.NewOpenAIResponsesAPIHandler(handlers.NewBaseAPIHandlers(&cfg.SDKConfig, manager))
	router := gin.New()
	router.GET("/v1/responses", h.ResponsesWebsocket)
	downstream := httptest.NewServer(router)
	t.Cleanup(downstream.Close)
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(downstream.URL, "http")+"/v1/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[]}`, model))); err != nil {
		t.Fatal(err)
	}
	return c, exec, attempts
}

func TestCodexWebsocketCloseArbitrationSameDownstream(t *testing.T) {
	for _, code := range []string{"usage_limit_reached", "insufficient_quota", "explicit:usage_limit_reached", "explicit:insufficient_quota"} {
		t.Run(code, func(t *testing.T) {
			c, exec, attempts := arbitrationClient(t, code, true, nil)
			_, payload, err := c.ReadMessage()
			if err != nil || gjson.GetBytes(payload, "response.id").String() != "replacement" {
				t.Fatalf("same socket completion = %s, %v", payload, err)
			}
			if attempts.Load() != 1 {
				t.Fatalf("fallback attempts = %d", attempts.Load())
			}
			sess := <-exec.session
			sess.connMu.Lock()
			hold := sess.disconnectHold
			sess.connMu.Unlock()
			if hold != nil {
				t.Fatal("retry did not cancel the disconnect hold")
			}
			model := gjson.GetBytes(payload, "response.model").String()
			if err := c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[]}`, model))); err != nil {
				t.Fatal(err)
			}
			_, payload, err = c.ReadMessage()
			if err != nil || gjson.GetBytes(payload, "response.id").String() != "next" {
				t.Fatalf("next turn on same socket = %s, %v", payload, err)
			}
		})
	}
}

func TestCodexWebsocketCloseArbitrationFinalRefusal(t *testing.T) {
	for _, code := range []string{"usage_limit_reached", "insufficient_quota", "explicit:usage_limit_reached", "explicit:insufficient_quota", "invalid_request_error"} {
		t.Run(code, func(t *testing.T) {
			c, _, attempts := arbitrationClient(t, code, false, nil)
			var payload []byte
			var err error
			for {
				_, payload, err = c.ReadMessage()
				if err != nil || gjson.GetBytes(payload, "type").String() == "error" {
					break
				}
			}
			if err != nil || !strings.Contains(string(payload), "original refusal") || !strings.Contains(string(payload), strings.TrimPrefix(code, "explicit:")) {
				t.Fatalf("original refusal before close = %s, %v", payload, err)
			}
			if _, _, err := c.ReadMessage(); err == nil {
				t.Fatal("final refusal did not close downstream")
			}
			if attempts.Load() != 0 {
				t.Fatal("unexpected fallback")
			}
		})
	}
}

func TestCodexWebsocketCloseArbitrationBound(t *testing.T) {
	gate := make(chan struct{})
	defer close(gate)
	c, exec, _ := arbitrationClient(t, "usage_limit_reached", true, gate)
	var sess *codexWebsocketSession
	select {
	case sess = <-exec.session:
	case <-time.After(5 * time.Second):
		t.Fatal("no teardown receipt")
	}
	sess.connMu.Lock()
	timer := sess.disconnectHold
	generation := sess.disconnectHoldGeneration
	sess.connMu.Unlock()
	if timer == nil || codexWebsocketDisconnectHold != 30*time.Second {
		t.Fatal("in-flight EOF has no fixed hold ceiling")
	}
	// Advance the timer callback deterministically while classification is blocked.
	sess.expireDisconnectHold(generation)
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("expired decision hold did not close downstream")
	}
}

func TestCodexWebsocketDisconnectHoldTimerAndStaleCallback(t *testing.T) {
	s := &codexWebsocketSession{upstreamDisconnectCh: make(chan error, 1)}
	s.connMu.Lock()
	s.startDisconnectHoldLocked(time.Millisecond)
	generation := s.disconnectHoldGeneration
	s.startDisconnectHoldLocked(time.Hour)
	if s.disconnectHoldGeneration != generation {
		t.Fatal("a second hold extended the deadline")
	}
	s.connMu.Unlock()
	select {
	case err := <-s.upstreamDisconnectCh:
		if err != context.DeadlineExceeded {
			t.Fatalf("expiry = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timer failed to publish close")
	}
	s = &codexWebsocketSession{upstreamDisconnectCh: make(chan error, 1)}
	s.connMu.Lock()
	s.startDisconnectHoldLocked(time.Hour)
	generation = s.disconnectHoldGeneration
	s.stopDisconnectHoldLocked()
	s.connMu.Unlock()
	s.expireDisconnectHold(generation)
	select {
	case <-s.upstreamDisconnectCh:
		t.Fatal("stale callback closed replacement session")
	default:
	}
}
