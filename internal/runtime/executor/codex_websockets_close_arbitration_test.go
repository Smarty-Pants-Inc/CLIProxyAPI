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
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	auth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	execution "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
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
	auto         *CodexAutoExecutor
}

// Keep the real observer instrumentation when v8 scopes an API-key executor.
// The promoted base method would otherwise discard this wrapper entirely.
func (e *arbitrationExecutor) ForAPIKey() auth.ProviderExecutor {
	clone := *e
	clone.CodexWebsocketsExecutor = e.CodexWebsocketsExecutor.ForAPIKey().(*CodexWebsocketsExecutor)
	if e.auto != nil {
		clone.auto = e.auto.ForAPIKey().(*CodexAutoExecutor)
	}
	return &clone
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
	if e.auto != nil {
		return e.auto.ExecuteStream(ctx, a, req, opts)
	}
	return e.CodexWebsocketsExecutor.ExecuteStream(ctx, a, req, opts)
}

// arbitrationOptions extends the harness: snapshot is a frame the primary sends between
// response.created and its refusal; httpStarted/httpRelease make the secondary an HTTP/SSE
// credential (websockets off) whose response waits for the release.
// httpSSE makes every fallback credential HTTP/SSE and serves this body ($MODEL replaced);
// tertiary adds a third such credential.
type arbitrationOptions struct {
	snapshot    string
	httpStarted chan<- struct{}
	httpRelease <-chan struct{}
	httpSSE     string
	tertiary    bool
	// other makes the secondary credential a non-Codex provider served by otherExecutor.
	other *otherProviderExecutor
}

// otherProviderExecutor is a non-Codex provider: the cross-provider replacement for a
// Codex WebSocket quota refusal. Its first response waits for release.
type otherProviderExecutor struct {
	started chan struct{}
	release chan struct{}
	model   string
	calls   atomic.Int32
}

func (*otherProviderExecutor) Identifier() string { return "arbitration-other" }
func (e *otherProviderExecutor) ExecuteStream(ctx context.Context, _ *auth.Auth, _ execution.Request, _ execution.Options) (*execution.StreamResult, error) {
	id := "next"
	if e.calls.Add(1) == 1 {
		id = "replacement"
		close(e.started)
		select {
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	chunks := make(chan execution.StreamChunk, 1)
	chunks <- execution.StreamChunk{Payload: []byte(fmt.Sprintf(`{"type":"response.completed","response":{"id":%q,"model":%q,"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"other provider answer"}]}]}}`, id, e.model))}
	close(chunks)
	return &execution.StreamResult{Chunks: chunks}, nil
}
func (*otherProviderExecutor) Execute(context.Context, *auth.Auth, execution.Request, execution.Options) (execution.Response, error) {
	return execution.Response{}, fmt.Errorf("not used")
}
func (*otherProviderExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) {
	return a, nil
}
func (*otherProviderExecutor) CountTokens(context.Context, *auth.Auth, execution.Request, execution.Options) (execution.Response, error) {
	return execution.Response{}, fmt.Errorf("not used")
}
func (*otherProviderExecutor) HttpRequest(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("not used")
}

func arbitrationClient(t *testing.T, refusal string, fallback bool, gate <-chan struct{}) (*websocket.Conn, *arbitrationExecutor, *atomic.Int32) {
	t.Helper()
	return arbitrationClientWith(t, refusal, fallback, gate, arbitrationOptions{})
}

func arbitrationClientWith(t *testing.T, refusal string, fallback bool, gate <-chan struct{}, o arbitrationOptions) (*websocket.Conn, *arbitrationExecutor, *atomic.Int32) {
	t.Helper()
	model := "arbitration-" + strings.ReplaceAll(t.Name(), "/", "-")
	rawTerminal, isRaw := strings.CutPrefix(refusal, "raw:")
	explicitStatus := strings.HasPrefix(refusal, "explicit:")
	refusal = strings.TrimPrefix(refusal, "explicit:")
	attempts := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			attempts.Add(1)
			if o.httpSSE != "" {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprint(w, strings.ReplaceAll(o.httpSSE, "$MODEL", model))
				return
			}
			close(o.httpStarted)
			<-o.httpRelease
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprintf(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"replacement\",\"model\":%q,\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"full http answer\"}]}]}}\n\n", model)
			return
		}
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
			if o.snapshot != "" {
				_ = c.WriteMessage(websocket.TextMessage, []byte(strings.ReplaceAll(o.snapshot, "$MODEL", model)))
			}
			terminal := fmt.Sprintf(`{"type":"response.failed","response":{"id":"primary","model":%q,"status":"failed","error":{"code":%q,"message":"original refusal"}}}`, model, refusal)
			if explicitStatus {
				terminal = fmt.Sprintf(`{"type":"error","status":429,"error":{"code":%q,"message":"original refusal"}}`, refusal)
			}
			if isRaw {
				terminal = strings.ReplaceAll(rawTerminal, "$MODEL", model)
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
	exec.auto = &CodexAutoExecutor{httpExec: NewCodexExecutor(cfg), wsExec: exec.CodexWebsocketsExecutor}
	t.Cleanup(func() { exec.CloseExecutionSession(auth.CloseAllExecutionSessionsID) })
	manager := auth.NewManager(nil, &auth.FillFirstSelector{}, nil)
	manager.SetConfig(cfg)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(exec)
	if o.other != nil {
		o.other.model = model
		manager.RegisterExecutor(o.other)
	}
	tokens := []string{"primary"}
	if fallback {
		tokens = append(tokens, "secondary")
	}
	if o.tertiary {
		tokens = append(tokens, "tertiary")
	}
	httpFallback := o.httpStarted != nil || o.httpSSE != ""
	for i, token := range tokens {
		id := fmt.Sprintf("%s-%d", t.Name(), i)
		provider := "codex"
		if i > 0 && o.other != nil {
			provider = o.other.Identifier()
		}
		registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		attrs := map[string]string{"api_key": token, "base_url": upstream.URL, "websockets": fmt.Sprint(i == 0 || !httpFallback)}
		if i == 0 {
			attrs["priority"] = "10" // the Codex WebSocket credential is tried first
		}
		_, err := manager.Register(context.Background(), &auth.Auth{ID: id, Provider: provider, Status: auth.StatusActive,
			Attributes: attrs, Metadata: map[string]any{"disable_cooling": false}})
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

// CLIProxyAPI#64 security P2: the final refusal written to the client is built
// from an allowlist; upstream credential and account fields never reach it.
func TestCodexWebsocketFinalRefusalRedactsUpstreamSecrets(t *testing.T) {
	const secrets = `"access_token":"canary-access-tok","refresh_token":"canary-refresh-tok","id_token":"eyJcanaryhdr.eyJcanarybody.canarysig","account_id":"canary-account-id","email":"canary@example.com","authorization":"Bearer canary-auth-hdr"`
	const message = `original refusal; Authorization: Bearer canary-bearer-msg account_id=canary-acct-msg for canary-mail@example.com token eyJcanaryjwt1.eyJcanaryjwt2.sig`
	bodies := map[string]string{
		"error_event":     `{"type":"error","status":429,` + secrets + `,"error":{"type":"usage_limit_reached","code":"usage_limit_reached","param":"model","resets_in_seconds":120,"message":"` + message + `",` + secrets + `}}`,
		"response_failed": `{"type":"response.failed",` + secrets + `,"response":{"id":"primary","model":"$MODEL","status":"failed",` + secrets + `,"error":{"type":"usage_limit_reached","code":"usage_limit_reached","param":"model","resets_in_seconds":120,"message":"` + message + `",` + secrets + `}}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			c, _, attempts := arbitrationClient(t, "raw:"+body, false, nil)
			var payload []byte
			var err error
			for {
				_, payload, err = c.ReadMessage()
				if err != nil || gjson.GetBytes(payload, "type").String() == "error" {
					break
				}
			}
			if err != nil {
				t.Fatalf("no final refusal: %v", err)
			}
			for _, leak := range []string{"canary", `"access_token"`, `"refresh_token"`, `"id_token"`, `"account_id"`, `"email"`, `"authorization"`, "eyJ", "@example.com"} {
				if strings.Contains(string(payload), leak) {
					t.Errorf("client refusal leaks %q: %s", leak, payload)
				}
			}
			if got := gjson.GetBytes(payload, "status").Int(); got != http.StatusTooManyRequests {
				t.Errorf("status = %d: %s", got, payload)
			}
			for key, want := range map[string]string{"error.type": "usage_limit_reached", "error.code": "usage_limit_reached", "error.param": "model", "error.resets_in_seconds": "120"} {
				if got := gjson.GetBytes(payload, key).String(); got != want {
					t.Errorf("%s = %q, want %q: %s", key, got, want, payload)
				}
			}
			if msg := gjson.GetBytes(payload, "error.message").String(); !strings.HasPrefix(msg, "original refusal") {
				t.Errorf("error.message = %q", msg)
			}
			if _, _, err := c.ReadMessage(); err == nil {
				t.Error("final refusal did not close downstream")
			}
			if attempts.Load() != 0 {
				t.Error("unexpected fallback")
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

// CLIProxyAPI#64 security round 3, P1 #1: an in_progress snapshot that already carries
// output has reached the client, so a later quota refusal + close must not replay the
// request on another credential. The client gets the refusal, then a close.
func TestCodexWebsocketOutputSnapshotQuotaNoReplay(t *testing.T) {
	snapshots := map[string]string{
		"in_progress_server_tool": `{"type":"response.in_progress","response":{"id":"primary","model":"$MODEL","output":[{"id":"ws_1","type":"web_search_call","status":"in_progress"}]}}`,
		"in_progress_text":        `{"type":"response.in_progress","response":{"id":"primary","model":"$MODEL","output":[{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"partial answer"}]}]}}`,
	}
	for name, snapshot := range snapshots {
		for _, code := range []string{"usage_limit_reached", "insufficient_quota"} {
			t.Run(name+"/"+code, func(t *testing.T) {
				c, _, attempts := arbitrationClientWith(t, code, true, nil, arbitrationOptions{snapshot: snapshot})
				var payload []byte
				var err error
				sawSnapshot := false
				for {
					_, payload, err = c.ReadMessage()
					if err != nil || gjson.GetBytes(payload, "type").String() == "error" {
						break
					}
					sawSnapshot = sawSnapshot || gjson.GetBytes(payload, "type").String() == "response.in_progress"
				}
				if !sawSnapshot {
					t.Error("output snapshot did not reach the client before the refusal")
				}
				if err != nil || !strings.Contains(string(payload), code) {
					t.Fatalf("refusal before close = %s, %v", payload, err)
				}
				if _, _, err := c.ReadMessage(); err == nil {
					t.Fatal("refusal did not close downstream")
				}
				if attempts.Load() != 0 {
					t.Fatalf("replayed on another credential after output reached the client: attempts=%d", attempts.Load())
				}
			})
		}
	}
}

// CLIProxyAPI#64 security round 3, P1 #2: the hold bounds only the wait for the decision.
// Once the HTTP fallback has started, expiry of the old hold must not close the socket;
// the client gets the fallback's full answer.
func TestCodexWebsocketHTTPFallbackOutlivesDecisionHold(t *testing.T) {
	gate := make(chan struct{})
	started := make(chan struct{})
	release := make(chan struct{})
	c, exec, attempts := arbitrationClientWith(t, "usage_limit_reached", true, gate, arbitrationOptions{httpStarted: started, httpRelease: release})
	var sess *codexWebsocketSession
	select {
	case sess = <-exec.session:
	case <-time.After(5 * time.Second):
		t.Fatal("no teardown receipt")
	}
	sess.connMu.Lock()
	hold := sess.disconnectHold
	generation := sess.disconnectHoldGeneration
	sess.connMu.Unlock()
	if hold == nil {
		t.Fatal("no decision hold while waiting for the decision")
	}
	close(gate)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP fallback did not start")
	}
	// The fallback outlives the bound: fire the old timer's callback deterministically.
	sess.expireDisconnectHold(generation)
	close(release)
	_, payload, err := c.ReadMessage()
	if err != nil || gjson.GetBytes(payload, "response.id").String() != "replacement" || !strings.Contains(string(payload), "full http answer") {
		t.Fatalf("HTTP fallback answer = %s, %v", payload, err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("fallback attempts = %d", attempts.Load())
	}
}

// CLIProxyAPI#64 security round 4, P2: the same rule on the HTTP/SSE fallback path. The primary
// WS quota refusal fails over to an HTTP-only credential; its SSE stream sends output, then a
// quota refusal. The client gets the output, the refusal, then a close; no further credential.
func TestCodexWebsocketHTTPFallbackOutputQuotaRefusal(t *testing.T) {
	snapshots := map[string]string{
		"in_progress_server_tool": `{"type":"response.in_progress","response":{"id":"fallback","model":"$MODEL","output":[{"id":"ws_1","type":"web_search_call","status":"in_progress"}]}}`,
		"in_progress_text":        `{"type":"response.in_progress","response":{"id":"fallback","model":"$MODEL","output":[{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"partial answer"}]}]}}`,
	}
	for name, snapshot := range snapshots {
		for _, code := range []string{"usage_limit_reached", "insufficient_quota"} {
			t.Run(name+"/"+code, func(t *testing.T) {
				sse := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"fallback\",\"model\":\"$MODEL\",\"output\":[]}}\n\n" +
					"event: response.in_progress\ndata: " + snapshot + "\n\n" +
					"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"fallback\",\"model\":\"$MODEL\",\"status\":\"failed\",\"error\":{\"code\":\"" + code + "\",\"message\":\"fallback refusal\"}}}\n\n"
				c, _, attempts := arbitrationClientWith(t, "usage_limit_reached", true, nil, arbitrationOptions{httpSSE: sse, tertiary: true})
				var payload []byte
				var err error
				sawOutput := false
				for {
					_, payload, err = c.ReadMessage()
					if err != nil || gjson.GetBytes(payload, "type").String() == "error" {
						break
					}
					sawOutput = sawOutput || (gjson.GetBytes(payload, "type").String() == "response.in_progress" && gjson.GetBytes(payload, "response.id").String() == "fallback")
				}
				if !sawOutput {
					t.Error("fallback output did not reach the client before the refusal")
				}
				if err != nil || !strings.Contains(string(payload), code) || !strings.Contains(string(payload), "fallback refusal") {
					t.Fatalf("fallback refusal before close = %s, %v", payload, err)
				}
				if _, _, err := c.ReadMessage(); err == nil {
					t.Fatal("refusal did not close downstream")
				}
				if attempts.Load() != 1 {
					t.Fatalf("credential attempts after primary = %d, want 1 (no replay after output)", attempts.Load())
				}
			})
		}
	}
}

// CLIProxyAPI#64 Astra round 3 P1: the handover is provider-independent. A Codex WebSocket quota
// refusal + EOF fails over to a non-Codex provider. Manager's attempt boundary ends the old hold;
// its timer callback, delivered after the replacement starts, must not close the client. The
// replacement completes, a second turn uses the same socket, and closing it releases the session.
func TestCodexWebsocketCrossProviderFallbackOutlivesDecisionHold(t *testing.T) {
	for _, code := range []string{"usage_limit_reached", "insufficient_quota"} {
		t.Run(code, func(t *testing.T) {
			gate := make(chan struct{})
			other := &otherProviderExecutor{started: make(chan struct{}), release: make(chan struct{})}
			c, exec, attempts := arbitrationClientWith(t, code, true, gate, arbitrationOptions{other: other})
			var sess *codexWebsocketSession
			select {
			case sess = <-exec.session:
			case <-time.After(5 * time.Second):
				t.Fatal("no teardown receipt from the Codex primary")
			}
			sess.connMu.Lock()
			hold := sess.disconnectHold
			generation := sess.disconnectHoldGeneration
			sess.connMu.Unlock()
			if hold == nil {
				t.Fatal("no decision hold while waiting for the decision")
			}
			close(gate)
			select {
			case <-other.started:
			case <-time.After(5 * time.Second):
				t.Fatal("other-provider fallback did not start")
			}
			sess.connMu.Lock()
			hold = sess.disconnectHold
			sess.connMu.Unlock()
			if hold != nil {
				t.Error("other-provider attempt did not end the Codex decision hold")
			}
			// The replacement outlives the bound: deliver the old timer's callback now.
			sess.expireDisconnectHold(generation)
			close(other.release)
			_, payload, err := c.ReadMessage()
			if err != nil || gjson.GetBytes(payload, "response.id").String() != "replacement" || !strings.Contains(string(payload), "other provider answer") {
				t.Fatalf("other-provider answer = %s, %v", payload, err)
			}
			if err := c.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"type":"response.create","model":%q,"input":[]}`, other.model))); err != nil {
				t.Fatal(err)
			}
			_, payload, err = c.ReadMessage()
			if err != nil || gjson.GetBytes(payload, "response.id").String() != "next" {
				t.Fatalf("next turn on same socket = %s, %v", payload, err)
			}
			if attempts.Load() != 0 || other.calls.Load() != 2 {
				t.Fatalf("codex fallback attempts = %d, other-provider calls = %d", attempts.Load(), other.calls.Load())
			}
			_ = c.Close()
			deadline := time.Now().Add(5 * time.Second)
			for {
				exec.store.mu.Lock()
				open := len(exec.store.sessions)
				exec.store.mu.Unlock()
				if open == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("downstream close left %d Codex session(s)", open)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
