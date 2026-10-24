package live

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const poolHumanKey = "synthetic-live-human-key"
const poolOtherHumanKey = "synthetic-live-other-human-key"
const poolAgentKey = "synthetic-live-agent-key"

// This fixture is explicitly trusted test composition, not a claim of genuine
// provider identity. Native OAuth proof semantics have separate runtime tests.
type poolLiveTestExecutor struct {
	captureExecutor
	send         func(context.Context, *auth.Auth, *http.Request) (*http.Response, error)
	acquisitions atomic.Int32
}

func (e *poolLiveTestExecutor) AcquirePoolIdentity(_ context.Context, a *auth.Auth) (*auth.Auth, auth.NativePoolIdentity, error) {
	e.acquisitions.Add(1)
	return a.Clone(), auth.NativePoolIdentity{Provider: "codex", AccountID: "synthetic-human-user", EntitlementID: "synthetic-human-entitlement"}, nil
}

func (e *poolLiveTestExecutor) HttpRequest(ctx context.Context, a *auth.Auth, req *http.Request) (*http.Response, error) {
	if e.send != nil {
		return e.send(ctx, a, req)
	}
	return e.captureExecutor.HttpRequest(ctx, a, req)
}

func newPoolLiveTestConfig() *config.Config {
	one := int64(1)
	pools := []config.AccountPool{
		{ID: "live-human", Org: "test-org", Class: config.PoolClassHuman, MaxInFlight: &one, Accounts: []config.PoolAccount{{Provider: "codex", AccountID: "synthetic-human-user", EntitlementID: "synthetic-human-entitlement"}}},
		{ID: "live-agent", Org: "test-org", Class: config.PoolClassAgent, MaxInFlight: &one, Accounts: []config.PoolAccount{{Provider: "codex", AccountID: "synthetic-agent-user", EntitlementID: "synthetic-agent-entitlement"}}},
	}
	cfg := &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{poolHumanKey, poolOtherHumanKey, poolAgentKey}, AccountPools: &pools, APIKeyPolicies: []config.APIKeyPolicy{
		{KeySHA256: config.APIKeyDigest(poolHumanKey), Pool: "live-human"},
		{KeySHA256: config.APIKeyDigest(poolOtherHumanKey), Pool: "live-human"},
		{KeySHA256: config.APIKeyDigest(poolAgentKey), Pool: "live-agent"},
	}}}
	cfg.WebsocketAuth = true
	cfg.Codex.LiveMediaRelay.Enabled = true
	cfg.Codex.LiveMediaRelay.MaxSessions = 8
	cfg.CommercialMode = true // no request logger/files in this synthetic fixture
	return cfg
}

func newPoolLiveTestManager(t *testing.T, cfg *config.Config, send func(context.Context, *auth.Auth, *http.Request) (*http.Response, error)) (*auth.Manager, *poolLiveTestExecutor) {
	t.Helper()
	manager := auth.NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	executor := &poolLiveTestExecutor{send: send}
	if err := manager.RegisterNativePoolExecutor(executor); err != nil {
		t.Fatal(err)
	}
	registerCredential(t, manager, &auth.Auth{ID: "synthetic-human-native", Provider: "codex", Status: auth.StatusActive, Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": "synthetic-human-access", "refresh_token": "synthetic-human-refresh", "account_id": "synthetic-human-entitlement"}})
	// Deliberately no registry advertisement for gpt-live-1-codex. Live selection
	// must enforce the admitted model without inventing an ordinary model entry.
	return manager, executor
}

func newPoolUnitHandler(t *testing.T, cfg *config.Config, media mediaRelayFactory, send func(context.Context, *auth.Auth, *http.Request) (*http.Response, error)) (*Handler, *auth.Manager, *poolLiveTestExecutor) {
	t.Helper()
	manager, executor := newPoolLiveTestManager(t, cfg, send)
	h := NewHandler(manager, cfg)
	h.mediaRelayMu.Lock()
	h.mediaRelay = media
	h.mediaRelayMu.Unlock()
	t.Cleanup(h.Close)
	return h, manager, executor
}

func servePoolUnit(h *Handler, key, method, path, body string, writer http.ResponseWriter) {
	c, _ := gin.CreateTestContext(writer)
	c.Request = httptest.NewRequest(method, path, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("userApiKey", key)
	c.Set("accessProvider", "config-inline")
	if method == http.MethodPost {
		h.Handle(c)
	} else {
		h.HandleSideband(c)
	}
}

func poolLiveBody() string {
	return `{"sdp":"client-offer","session":{"model":"gpt-live-1-codex","instructions":"original"}}`
}
func poolLiveResponse() *http.Response {
	return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/sdp"}, "Location": {"/v1/live/rtc_test"}}, Body: io.NopCloser(strings.NewReader("upstream-answer"))}
}

func TestPoolLiveHandlerOneLeaseAndForeignOwner(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	h, manager, executor := newPoolUnitHandler(t, cfg, echoMediaRelay{}, func(_ context.Context, _ *auth.Auth, req *http.Request) (*http.Response, error) {
		if req.URL.String() != upstreamCallURL {
			t.Errorf("bootstrap target = %s", req.URL)
		}
		return poolLiveResponse(), nil
	})
	rr := httptest.NewRecorder()
	servePoolUnit(h, poolHumanKey, http.MethodPost, "/v1/live", poolLiveBody(), rr)
	if rr.Code != 201 {
		t.Fatalf("POST = %d %s", rr.Code, rr.Body)
	}
	stored, exists := h.sessions.peek("rtc_test")
	if !exists || stored.poolOp == nil || stored.lifetime == nil {
		t.Fatal("call attribution not retained")
	}
	rr = httptest.NewRecorder()
	servePoolUnit(h, poolHumanKey, http.MethodPost, "/v1/live", poolLiveBody(), rr)
	if rr.Code != 429 {
		t.Fatalf("second POST = %d %s", rr.Code, rr.Body)
	}
	if executor.acquisitions.Load() != 1 {
		t.Fatal("capacity denial reached identity acquisition")
	}
	// A different key in the same pool is not the call issuer.
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/v1/live/rtc_test", nil)
	c.Request.Header.Set("Connection", "Upgrade")
	c.Request.Header.Set("Upgrade", "websocket")
	c.Params = gin.Params{{Key: "call_id", Value: "rtc_test"}}
	c.Set("userApiKey", poolOtherHumanKey)
	c.Set("accessProvider", "config-inline")
	h.HandleSideband(c)
	if c.Writer.Status() != 403 {
		t.Fatalf("foreign owner status = %d", c.Writer.Status())
	}
	if _, _, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall); err == nil {
		t.Fatal("foreign join released lease")
	}
	h.sessions.complete(stored, "test_done")
	stored.lifetime.waitClosed()
	_, op, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatalf("completed call retained slot: %v", err)
	}
	op.Finish()
}

func TestPoolLivePayloadBarrierHelperAndHandler(t *testing.T) {
	for _, field := range []string{"session.model", "sdp", "session", "safe"} {
		t.Run(field, func(t *testing.T) {
			cfg := newPoolLiveTestConfig()
			models := []config.PayloadModelRule{{Name: defaultLiveModel, Protocol: "openai-response", FromProtocol: "openai-response", Match: []map[string]any{{"sdp": "relay-offer", "session.instructions": "original"}}}}
			if field == "safe" {
				secondPass := append([]config.PayloadModelRule(nil), models...)
				secondPass[0].Match = []map[string]any{{"sdp": "relay-offer", "session.instructions": "configured"}}
				cfg.Payload.Override = []config.PayloadRule{
					{Models: secondPass, Params: map[string]any{"session.instructions": "applied-twice"}},
					{Models: models, Params: map[string]any{"session.instructions": "configured"}},
				}
			} else {
				cfg.Payload.Filter = []config.PayloadFilterRule{{Models: models, Params: []string{field}}}
			}
			original, prepared, model, err := canonicalPoolLiveRequest([]byte(poolLiveBody()), "application/json")
			if err != nil {
				t.Fatal(err)
			}
			prepared, _, _ = replaceCallRequestSDP(prepared, "application/json", "relay-offer")
			final, _, err := finalizePoolLivePayload(context.Background(), cfg, model, "application/json", original, prepared, nil)
			if (err == nil) != (field == "safe") {
				t.Fatalf("helper final=%s err=%v", final, err)
			}
			var sends atomic.Int32
			h, _, _ := newPoolUnitHandler(t, cfg, &fakeMediaRelay{session: &fakeMediaSession{downstreamSDP: "client-answer"}, upstreamOffer: "relay-offer"}, func(_ context.Context, _ *auth.Auth, req *http.Request) (*http.Response, error) {
				sends.Add(1)
				wire, _ := io.ReadAll(req.Body)
				var body struct {
					SDP     string                               `json:"sdp"`
					Session struct{ Model, Instructions string } `json:"session"`
				}
				if json.Unmarshal(wire, &body) != nil || body.SDP != "relay-offer" || body.Session.Model != defaultLiveModel || body.Session.Instructions != "configured" {
					t.Errorf("final wire = %s", wire)
				}
				return poolLiveResponse(), nil
			})
			rr := httptest.NewRecorder()
			servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
			if field == "safe" {
				if rr.Code != 201 || sends.Load() != 1 {
					t.Fatalf("safe rule status=%d sends=%d body=%s", rr.Code, sends.Load(), rr.Body)
				}
			} else if rr.Code != 503 || sends.Load() != 0 {
				t.Fatalf("unsafe rule status=%d sends=%d", rr.Code, sends.Load())
			}
		})
	}
}

func TestPoolLiveConfiguredModelSwitchForbidden(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: defaultLiveModel}}, Params: map[string]any{"session.model": "gpt-5.4"}}}
	var sends atomic.Int32
	h, manager, _ := newPoolUnitHandler(t, cfg, echoMediaRelay{}, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
		sends.Add(1)
		return poolLiveResponse(), nil
	})
	rr := httptest.NewRecorder()
	servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
	if rr.Code != 403 || sends.Load() != 0 || !strings.Contains(rr.Body.String(), "api_key_model_forbidden") {
		t.Fatalf("model override status=%d sends=%d body=%s", rr.Code, sends.Load(), rr.Body)
	}
	_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	next.Finish()
}

// Trust boundary keep reason: field filtering must not restore session.model or
// a direct client SDP after the last payload barrier; originals drive rule gates.
func TestPoolLiveCanonicalMultipartAndOverrides(t *testing.T) {
	body := []byte(multipartBody("boundary", "client-offer", `{"model":"gpt-realtime","instructions":"original"}`))
	original, prepared, model, err := canonicalPoolLiveRequest(body, "multipart/form-data; boundary=boundary")
	if err != nil || model != defaultLiveModel || !json.Valid(original) || !json.Valid(prepared) {
		t.Fatalf("canonical: %s %s %s %v", original, prepared, model, err)
	}
	for _, path := range []string{"session.model", "sdp"} {
		cfg := newPoolLiveTestConfig()
		cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: defaultLiveModel}}, Params: map[string]any{path: "unsafe"}}}
		if _, _, err := finalizePoolLivePayload(context.Background(), cfg, model, "application/json", original, prepared, nil); err == nil {
			t.Fatalf("override %s accepted", path)
		}
	}
}

type barrierMediaSession struct {
	fakeMediaSession
	peerClosed  chan struct{}
	waitEntered chan struct{}
	workersDone chan struct{}
	once        sync.Once
}

func (m *barrierMediaSession) CloseWithReason(reason string) error {
	m.once.Do(func() {
		m.fakeMediaSession.CloseWithReason(reason)
		if m.closeHandler != nil {
			m.closeHandler(reason)
		}
		close(m.peerClosed)
	})
	return nil
}
func (m *barrierMediaSession) WaitClosed() error { close(m.waitEntered); <-m.workersDone; return nil }

func TestPoolLiveFinalizerClosesPeersBeforeMediaWaitAndRelease(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	manager, _ := newPoolLiveTestManager(t, cfg, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
		return poolLiveResponse(), nil
	})
	ctx, op, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	// Transfer is only valid after the genuine narrow bootstrap path has
	// selected a proven identity and closed its successful response body.
	selected, err := manager.SelectPoolLiveAuth(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	request, err := manager.NewPoolLiveRequest(ctx, selected, "", []byte(poolLiveBody()), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := manager.SendPoolLiveRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	_, lifetime := newLiveCallLifetime(ctx, op)
	media := &barrierMediaSession{peerClosed: make(chan struct{}), waitEntered: make(chan struct{}), workersDone: make(chan struct{})}
	lifetime.setMedia(media)
	media.SetCloseHandler(lifetime.requestClose) // reentrant close is request-only
	done, _ := lifetime.beginWork()
	if err = lifetime.transfer("rtc_barrier"); err != nil {
		t.Fatal(err)
	}
	lifetime.requestClose("test")
	if _, ok := lifetime.beginWork(); ok {
		t.Fatal("registered after closing")
	}
	select {
	case <-media.peerClosed:
		t.Fatal("media closed before bootstrap/join terminated")
	default:
	}
	done()
	waitLiveEvent(t, media.peerClosed, "peer close before worker wait")
	waitLiveEvent(t, media.waitEntered, "media-worker wait")
	if _, _, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall); err == nil {
		t.Fatal("slot released while media worker blocked")
	}
	concurrent := make(chan struct{})
	go func() { lifetime.requestClose("concurrent"); lifetime.waitClosed(); close(concurrent) }()
	select {
	case <-concurrent:
		t.Fatal("concurrent close returned before cleanup")
	default:
	}
	close(media.workersDone)
	waitLiveEvent(t, concurrent, "finalizer completion")
	_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	next.Finish()
}

func TestPoolLiveWriteFailureExpiryReplacementShutdown(t *testing.T) {
	for _, event := range []string{"write", "expiry", "replacement", "shutdown"} {
		t.Run(event, func(t *testing.T) {
			cfg := newPoolLiveTestConfig()
			h, manager, _ := newPoolUnitHandler(t, cfg, echoMediaRelay{}, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
				return poolLiveResponse(), nil
			})
			if event == "write" {
				servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), &failingHTTPWriter{header: make(http.Header)})
			} else {
				rr := httptest.NewRecorder()
				servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
				if rr.Code != 201 {
					t.Fatalf("bootstrap %d %s", rr.Code, rr.Body)
				}
				stored, _ := h.sessions.peek("rtc_test")
				switch event {
				case "expiry":
					h.sessions.expire(stored.callID, stored.token)
				case "replacement":
					h.sessions.put(stored.callID, liveSession{})
				case "shutdown":
					h.Close()
				}
				stored.lifetime.waitClosed()
			}
			_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
			if err != nil {
				t.Fatalf("%s retained slot: %v", event, err)
			}
			next.Finish()
		})
	}
}

func TestPoolLiveBootstrapCancelJoinsMediaBeforeRelease(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	media := &barrierMediaSession{peerClosed: make(chan struct{}), waitEntered: make(chan struct{}), workersDone: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(media.workersDone) }) }
	defer release()
	sendEntered := make(chan struct{})
	h, manager, _ := newPoolUnitHandler(t, cfg, &barrierMediaFactory{session: media}, func(ctx context.Context, _ *auth.Auth, _ *http.Request) (*http.Response, error) {
		close(sendEntered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/live", strings.NewReader(poolLiveBody())).WithContext(ctx)
		c.Request.Header.Set("Content-Type", "application/json")
		c.Set("userApiKey", poolHumanKey)
		c.Set("accessProvider", "config-inline")
		h.Handle(c)
		close(finished)
	}()
	waitLiveEvent(t, sendEntered, "bootstrap send")
	cancel()
	waitLiveEvent(t, media.peerClosed, "pretransfer peer close")
	waitLiveEvent(t, media.waitEntered, "pretransfer media join")
	if _, _, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall); err == nil {
		t.Fatal("cancel released capacity before media cleanup")
	}
	release()
	waitLiveEvent(t, finished, "canceled bootstrap completion")
	_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	next.Finish()
}

type barrierMediaFactory struct{ session *barrierMediaSession }

func (f *barrierMediaFactory) NewSession(context.Context, string, mediaSessionRoute) (mediaRelaySession, string, error) {
	return f.session, "relay-offer", nil
}

func TestPoolLiveStoreMissingAndSendFailureFinalize(t *testing.T) {
	for _, failure := range []string{"store", "send", "body"} {
		t.Run(failure, func(t *testing.T) {
			cfg := newPoolLiveTestConfig()
			media := &fakeMediaSession{downstreamSDP: "client-answer"}
			responseBody := &trackedResponseBody{Reader: strings.NewReader("answer")}
			var h *Handler
			h, manager, _ := newPoolUnitHandler(t, cfg, &fakeMediaRelay{session: media, upstreamOffer: "relay-offer"}, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
				resp := poolLiveResponse()
				if failure == "store" {
					h.sessions = nil
				}
				if failure == "send" {
					resp.Body = responseBody
					return resp, errors.New("synthetic send failure")
				}
				if failure == "body" {
					resp.Body = &errorResponseBody{payload: []byte("partial")}
				}
				return resp, nil
			})
			rr := httptest.NewRecorder()
			servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
			if rr.Code < 400 || !media.closed.Load() {
				t.Fatalf("%s status=%d mediaClosed=%v", failure, rr.Code, media.closed.Load())
			}
			if failure == "send" && !responseBody.closed.Load() {
				t.Fatal("response plus error leaked body")
			}
			_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
			if err != nil {
				t.Fatalf("%s retained slot: %v", failure, err)
			}
			next.Finish()
		})
	}
}

func TestPoolLiveConcurrentHandlerCloseWaits(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	media := &barrierMediaSession{fakeMediaSession: fakeMediaSession{downstreamSDP: "client-answer"}, peerClosed: make(chan struct{}), waitEntered: make(chan struct{}), workersDone: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(media.workersDone) }) }
	defer release()
	h, manager, _ := newPoolUnitHandler(t, cfg, &barrierMediaFactory{session: media}, func(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
		return poolLiveResponse(), nil
	})
	rr := httptest.NewRecorder()
	servePoolUnit(h, poolHumanKey, "POST", "/v1/live", poolLiveBody(), rr)
	if rr.Code != 201 {
		t.Fatalf("bootstrap %d %s", rr.Code, rr.Body)
	}
	first, second := make(chan struct{}), make(chan struct{})
	go func() { h.Close(); close(first) }()
	waitLiveEvent(t, media.waitEntered, "shutdown media wait")
	go func() { h.Close(); close(second) }()
	if _, _, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall); err == nil {
		t.Fatal("shutdown released capacity before media completion")
	}
	select {
	case <-first:
		t.Fatal("first Handler.Close returned early")
	default:
	}
	select {
	case <-second:
		t.Fatal("concurrent Handler.Close returned early")
	default:
	}
	release()
	waitLiveEvent(t, first, "first Handler.Close")
	waitLiveEvent(t, second, "concurrent Handler.Close")
	_, next, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	next.Finish()
}

func TestPoolLiveCanonicalPrepBeforeAdmission(t *testing.T) {
	cfg := newPoolLiveTestConfig()
	h, manager, executor := newPoolUnitHandler(t, cfg, echoMediaRelay{}, nil)
	_, held, err := manager.BeginPoolOperation(context.Background(), poolHumanKey, defaultLiveModel, auth.PoolLiveCall)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Finish()
	for _, body := range []string{`{`, `null`, `{"sdp":"offer","session":null}`, `{"sdp":"offer","session":{"model":7}}`, `{"sdp":"offer","model":7}`, `{"sdp":"one","sdp":"two"}`, `{"sdp":"offer","session":{"model":"other","model":"gpt-live-1-codex"}}`} {
		rr := httptest.NewRecorder()
		servePoolUnit(h, poolHumanKey, "POST", "/v1/live", body, rr)
		if rr.Code != 400 {
			t.Fatalf("parse must precede full-pool admission: %d %s", rr.Code, rr.Body)
		}
	}
	if executor.acquisitions.Load() != 0 {
		t.Fatal("invalid bodies reached credential acquisition")
	}
}

func TestPoolLiveControlsClosedSet(t *testing.T) {
	for _, data := range []string{`{"type":"session.close"}`, `{"type":"session.context.append","content":[{"type":"input_text","text":"hello"}]}`, `{"type":"delegation.context.append","delegation_item_id":"item","channel":"commentary","content":[{"type":"input_text","text":"hello"}]}`} {
		if err := validatePoolLiveControl([]byte(data), true); err != nil {
			t.Errorf("valid %s: %v", data, err)
		}
	}
	for _, data := range []string{`{"type":"session.update","session":{"model":"other"}}`, `{"type":"session.close","model":"other"}`, `{"type":"unknown"}`, `{"type":"session.context.append","content":[{"type":"input_text","text":"x","model":"other"}]}`, `{"type":"session.context.append","content":null}`, `{"type":"response.create","type":"session.close"}`, `{"type":"response.create","\u0074ype":"session.close"}`, `{"type":"session.context.append","content":[{"type":"input_audio","type":"input_text","text":"x"}]}`} {
		if err := validatePoolLiveControl([]byte(data), true); err == nil {
			t.Errorf("unsafe accepted %s", data)
		}
	}
	if !errors.Is(validatePoolLiveControl([]byte(`{"type":"session.close"}`), false), errPoolLiveControl) {
		t.Fatal("binary control accepted")
	}
}
