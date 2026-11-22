package helps_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	native "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/translator"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// These tests deliberately use the real API authentication/admission middleware,
// real native executors, official token/profile implementations and final guards.
// Only transport construction is replaced, BELOW both independent guards. The
// transport has no Internet fallback and does not rewrite native URL/headers/body.
const wireCodexModel = "gpt-5.4"
const wireClaudeModel = "claude-sonnet-4-5"

type wireAccount struct{ name, account, entitlement, access, refresh, id string }
type wireWrite struct {
	account, target, authorization, entitlement string
	body                                        []byte
}
type wireFixture struct {
	t                     *testing.T
	provider, model, path string
	manager               *auth.Manager
	server                *api.Server
	upstream              *httptest.Server
	transport             *http.Transport
	mu                    sync.Mutex
	accounts              map[string]*wireAccount
	writes                []wireWrite
	controls              map[string]int
	identity              func(*wireAccount) (string, string)
	business              func(http.ResponseWriter, *http.Request, *wireAccount, []byte)
	closeGate             func(*http.Request, *http.Response) *wireCloseGate
}
type wireMappedTransport struct{ f *wireFixture }

type wireTransitionHook struct {
	mu      sync.Mutex
	entries []*log.Entry
}

func (h *wireTransitionHook) Levels() []log.Level { return log.AllLevels }
func (h *wireTransitionHook) Fire(entry *log.Entry) error {
	h.mu.Lock()
	h.entries = append(h.entries, entry)
	h.mu.Unlock()
	return nil
}
func (h *wireTransitionHook) transitionCount(label string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, entry := range h.entries {
		if entry.Message == "native credential identity moved between pools; credential quarantined" && entry.Data["credential_label"] == label {
			count++
		}
	}
	return count
}

func (m wireMappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f := m.f
	// Exact full targets, not host-only matching. Unexpected requests fail here
	// and can never reach either the fixture or the Internet.
	allowed := (r.Method == "POST" && r.URL.String() == codexauth.TokenURL) ||
		(r.Method == "GET" && r.URL.String() == claudeauth.ProfileURL) ||
		(r.Method == "POST" && r.URL.String() == claudeauth.TokenURL) ||
		(r.Method == "POST" && r.URL.String() == "https://chatgpt.com/backend-api/codex/responses") ||
		(r.Method == "POST" && r.URL.String() == "https://chatgpt.com/backend-api/codex/responses/compact") ||
		(r.Method == "POST" && r.URL.String() == "https://api.anthropic.com/v1/messages?beta=true")
	if !allowed {
		f.t.Errorf("unexpected native target %s %s", r.Method, r.URL)
		return nil, fmt.Errorf("fixture refused target")
	}
	response, err := f.transport.RoundTrip(r)
	if err == nil && f.closeGate != nil {
		if gate := f.closeGate(r, response); gate != nil {
			response.Body = &wireGatedBody{ReadCloser: response.Body, gate: gate}
		}
	}
	return response, err
}

type wireCloseGate struct {
	started, release chan struct{}
	once             sync.Once
	releaseOnce      sync.Once
}

func newWireCloseGate() *wireCloseGate {
	return &wireCloseGate{started: make(chan struct{}), release: make(chan struct{})}
}
func (g *wireCloseGate) allow() { g.releaseOnce.Do(func() { close(g.release) }) }

type wireGatedBody struct {
	io.ReadCloser
	gate *wireCloseGate
}

func (b *wireGatedBody) Close() error {
	b.gate.once.Do(func() { close(b.gate.started) })
	<-b.gate.release
	return b.ReadCloser.Close()
}

func newWireFixture(t *testing.T, provider string) *wireFixture {
	t.Helper()
	f := &wireFixture{t: t, provider: provider, model: wireCodexModel, path: "/v1/responses", accounts: map[string]*wireAccount{}, controls: map[string]int{}}
	if provider == "claude" {
		f.model = wireClaudeModel
		f.path = "/v1/messages"
	}
	for i, name := range []string{"a", "b", "human"} {
		a := &wireAccount{name: name, account: "user-" + name, entitlement: "entitlement-" + name, access: "synthetic-access-" + name, refresh: t.Name() + "-refresh-" + name, id: t.Name() + "-" + name}
		if provider == "claude" {
			a.account = fmt.Sprintf("11111111-1111-4111-8111-%012d", i+1)
			a.entitlement = fmt.Sprintf("22222222-2222-4222-8222-%012d", i+1)
			a.access = "sk-ant-oat01-synthetic-" + name
		}
		f.accounts[name] = a
	}
	f.identity = func(a *wireAccount) (string, string) { return a.account, a.entitlement }
	f.business = f.success
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.transport = f.upstream.Client().Transport.(*http.Transport).Clone()
	f.transport.Proxy = nil
	// Trust only the fixture certificate while retaining the approved wire Host.
	f.transport.TLSClientConfig.ServerName = f.upstream.Certificate().DNSNames[0]
	f.transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case "auth.openai.com:443", "chatgpt.com:443", "api.anthropic.com:443", "platform.claude.com:443":
		default:
			return nil, fmt.Errorf("fixture refused dial %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, f.upstream.Listener.Addr().String())
	}
	helps.NativePoolTransportForTest(t, wireMappedTransport{f})
	t.Cleanup(func() { f.transport.CloseIdleConnections(); f.upstream.Close() })
	raw := fmt.Sprintf(`ws-auth: true
request-retry: 0
max-retry-credentials: 3
codex:
  live-media-relay:
    enabled: true
access:
  api-keys: ["wire-a", "wire-b", "wire-human"]
  account-pools:
    - id: agents
      org: wire
      class: agent
      max-in-flight: 1
      accounts:
        - {provider: %s, account-id: %q, entitlement-id: %q}
        - {provider: %s, account-id: %q, entitlement-id: %q}
    - id: humans
      org: wire
      class: human
      max-in-flight: 1
      accounts:
        - {provider: %s, account-id: %q, entitlement-id: %q}
  api-key-policies:
    - {key-sha256: "%x", pool: agents}
    - {key-sha256: "%x", pool: agents}
    - {key-sha256: "%x", pool: humans}
`, provider, f.accounts["a"].account, f.accounts["a"].entitlement, provider, f.accounts["b"].account, f.accounts["b"].entitlement, provider, f.accounts["human"].account, f.accounts["human"].entitlement, sha256.Sum256([]byte("wire-a")), sha256.Sum256([]byte("wire-b")), sha256.Sum256([]byte("wire-human")))
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	selector := auth.NewSessionAffinitySelector(&auth.FillFirstSelector{})
	t.Cleanup(selector.Stop)
	f.manager = auth.NewManager(nil, selector, nil)
	f.manager.SetConfig(cfg)
	var exec auth.ProviderExecutor = native.NewCodexExecutor(cfg)
	if provider == "claude" {
		exec = native.NewClaudeExecutor(cfg)
	}
	if err = f.manager.RegisterNativePoolExecutor(exec); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "human"} {
		a := f.accounts[name]
		_, err = f.manager.Register(context.Background(), &auth.Auth{ID: a.id, Label: "wire-" + name, Provider: provider, Status: auth.StatusActive, Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": a.access, "refresh_token": a.refresh, "account_id": "untrusted-file-entitlement", "account_uuid": "untrusted-file-account", "verified": true, "claude_account_profile_checked_at": "2099-01-01T00:00:00Z"}})
		if err != nil {
			t.Fatal(err)
		}
		registry.GetGlobalRegistry().RegisterClient(a.id, provider, []*registry.ModelInfo{{ID: f.model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(a.id) })
	}
	f.server = api.NewServer(cfg, f.manager, sdkaccess.NewManager(), "")
	t.Cleanup(func() {
		if errStop := f.server.Stop(context.Background()); errStop != nil {
			t.Error(errStop)
		}
	})
	return f
}
func (f *wireFixture) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(500)
		return
	}
	target := "https://" + r.Host + r.URL.RequestURI()
	f.mu.Lock()
	f.controls[target]++
	f.mu.Unlock()
	if target == claudeauth.TokenURL {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			f.t.Error("wrong Claude official refresh request")
		}
		var refreshRequest struct {
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(body, &refreshRequest) != nil {
			f.t.Error("invalid Claude official refresh request")
		}
		var a *wireAccount
		for _, candidate := range f.accounts {
			if candidate.refresh == refreshRequest.RefreshToken {
				a = candidate
			}
		}
		if a == nil {
			f.t.Error("unknown Claude refresh token")
			w.WriteHeader(400)
			return
		}
		a.access += "-refreshed"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": a.access, "refresh_token": a.refresh, "token_type": "bearer", "expires_in": 3600})
		return
	}
	if target == codexauth.TokenURL {
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			f.t.Error("wrong official token request")
		}
		formReq, _ := http.NewRequest("POST", "http://fixture.invalid", strings.NewReader(string(body)))
		formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = formReq.ParseForm()
		var a *wireAccount
		for _, candidate := range f.accounts {
			if candidate.refresh == formReq.Form.Get("refresh_token") {
				a = candidate
			}
		}
		if a == nil || formReq.Form.Get("grant_type") != "refresh_token" || formReq.Form.Get("client_id") != codexauth.ClientID {
			f.t.Error("unexpected native refresh form")
			w.WriteHeader(400)
			return
		}
		account, entitlement := f.identity(a)
		claims, _ := json.Marshal(map[string]any{"sub": "sub-" + a.name, "https://api.openai.com/auth": map[string]any{"chatgpt_user_id": account, "chatgpt_account_id": entitlement}})
		token := "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".synthetic"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": a.access, "refresh_token": a.refresh, "id_token": token, "expires_in": 3600})
		return
	}
	var a *wireAccount
	for _, candidate := range f.accounts {
		if r.Header.Get("Authorization") == "Bearer "+candidate.access {
			a = candidate
		}
	}
	if a == nil {
		f.t.Error("unknown Authorization on native wire")
		w.WriteHeader(401)
		return
	}
	if target == claudeauth.ProfileURL {
		if r.Method != "GET" || len(body) != 0 {
			f.t.Error("wrong official profile request")
		}
		account, entitlement := f.identity(a)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"account": map[string]any{"uuid": account}, "organization": map[string]any{"uuid": entitlement}})
		return
	}
	if r.Method != "POST" {
		f.t.Error("unexpected business method")
		w.WriteHeader(500)
		return
	}
	if f.provider == "codex" && (r.Header.Get("Chatgpt-Account-Id") != a.entitlement || r.Host != "chatgpt.com") {
		f.t.Error("wrong native account header/host")
	}
	if f.provider == "claude" {
		var payload struct {
			Metadata struct {
				UserID string `json:"user_id"`
			} `json:"metadata"`
		}
		_ = json.Unmarshal(body, &payload)
		var identity struct {
			Account string `json:"account_uuid"`
		}
		if json.Unmarshal([]byte(payload.Metadata.UserID), &identity) != nil || identity.Account != a.account || r.Host != "api.anthropic.com" {
			f.t.Errorf("wrong Claude native wire identity: %s", body)
		}
	}
	var payload struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Model != f.model {
		f.t.Error("wrong native model/body")
	}
	f.mu.Lock()
	f.writes = append(f.writes, wireWrite{a.name, target, r.Header.Get("Authorization"), r.Header.Get("Chatgpt-Account-Id"), append([]byte(nil), body...)})
	f.mu.Unlock()
	f.business(w, r, a, body)
}
func (f *wireFixture) success(w http.ResponseWriter, r *http.Request, _ *wireAccount, body []byte) {
	if strings.HasSuffix(r.URL.Path, "/compact") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"compact","object":"response.compaction","model":%q,"output":[{"type":"compaction","encrypted_content":"native-direct-signed"}]}`, f.model)
		return
	}
	var request struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &request)
	if f.provider == "claude" {
		if !request.Stream {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"msg","type":"message","role":"assistant","model":%q,"content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`, f.model)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n", f.model)
		fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":%q}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":%q,\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n", f.model, f.model)
}
func (f *wireFixture) payload(stream bool) string {
	if f.provider == "claude" {
		return fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"hello"}],"max_tokens":32,"stream":%t}`, f.model, stream)
	}
	return fmt.Sprintf(`{"model":%q,"input":"hello","stream":%t}`, f.model, stream)
}
func (f *wireFixture) request(ctx context.Context, key, path, body string) *http.Request {
	r := httptest.NewRequest("POST", path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Session-Id", "shared-native-conversation")
	return r
}
func (f *wireFixture) post(key, path, body string) (int, []byte) {
	f.t.Helper()
	rr := httptest.NewRecorder()
	f.server.Handler().ServeHTTP(rr, f.request(context.Background(), key, path, body))
	return rr.Code, rr.Body.Bytes()
}
func (f *wireFixture) snapshot() []wireWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wireWrite(nil), f.writes...)
}
func (f *wireFixture) requireStatus(key, path, body string, want int) []byte {
	f.t.Helper()
	status, response := f.post(key, path, body)
	if status != want {
		f.t.Fatalf("%s %s status=%d want=%d body=%s", key, path, status, want, response)
	}
	return response
}

func TestPoolNativeGatewayWireRetryAndLaterTurn(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, stream := range []bool{false, true} {
			for _, failure := range []int{503, 429} {
				t.Run(fmt.Sprintf("%s/stream=%v/failure=%d", provider, stream, failure), func(t *testing.T) {
					f := newWireFixture(t, provider)
					f.requireStatus("wire-human", f.path, f.payload(stream), 200)
					baseline := len(f.snapshot())
					failed := false
					f.business = func(w http.ResponseWriter, r *http.Request, a *wireAccount, body []byte) {
						if !failed {
							failed = true
							w.WriteHeader(failure)
							fmt.Fprint(w, `{"error":{"message":"synthetic retry"}}`)
							return
						}
						f.success(w, r, a, body)
					}
					f.requireStatus("wire-a", f.path, f.payload(stream), 200)
					writes := f.snapshot()[baseline:]
					if len(writes) != 2 || writes[0].account == writes[1].account {
						t.Fatalf("retry did not change same-pool account: %+v", writes)
					}
					f.requireStatus("wire-b", f.path, f.payload(stream), 200)
					writes = f.snapshot()[baseline:]
					if len(writes) != 3 {
						t.Fatalf("later-turn writes=%d", len(writes))
					}
					for _, write := range writes {
						if write.account == "human" {
							t.Fatal("agent wrote human credentials")
						}
						a := f.accounts[write.account]
						if write.authorization != "Bearer "+a.access {
							t.Fatal("Authorization not attributable to pool member")
						}
					}
					f.mu.Lock()
					defer f.mu.Unlock()
					control := codexauth.TokenURL
					if provider == "claude" {
						control = claudeauth.ProfileURL
					}
					if f.controls[control] != 3 {
						t.Fatalf("official native acquisition calls=%d, want all three accounts", f.controls[control])
					}
				})
			}
		}
	}
}

func TestPoolNativeGatewayCompactionSignerWire(t *testing.T) {
	for _, production := range []string{"direct", "responses-sse"} {
		t.Run(production, func(t *testing.T) {
			f := newWireFixture(t, "codex")
			produce := func(key, encrypted string) []byte {
				t.Helper()
				if production == "direct" {
					return f.requireStatus(key, "/v1/responses/compact", f.payload(false), 200)
				}
				f.business = func(w http.ResponseWriter, _ *http.Request, _ *wireAccount, _ []byte) {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"model\":%q}}\n\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"compaction\",\"encrypted_content\":%q}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"model\":%q,\"status\":\"completed\",\"output\":[{\"type\":\"compaction\",\"encrypted_content\":%q}]}}\n\n", f.model, encrypted, f.model, encrypted)
				}
				return f.requireStatus(key, f.path, f.payload(true), 200)
			}
			// Give human and agent different opaque blocks even on direct compaction.
			originalSuccess := f.business
			if production == "direct" {
				f.business = func(w http.ResponseWriter, r *http.Request, a *wireAccount, b []byte) {
					if a.name == "human" {
						fmt.Fprintf(w, `{"output":[{"type":"compaction","encrypted_content":"native-human-signed"}]}`)
						return
					}
					originalSuccess(w, r, a, b)
				}
			}
			produce("wire-human", "native-human-signed")
			output := produce("wire-a", "native-agent-signed")
			encrypted := "native-agent-signed"
			if production == "direct" {
				encrypted = "native-direct-signed"
			}
			if !strings.Contains(string(output), encrypted) {
				t.Fatalf("native compaction not delivered: %s", output)
			}
			produced := f.snapshot()
			signer := produced[len(produced)-1].account
			continuation := fmt.Sprintf(`{"model":%q,"input":[{"type":"compaction","encrypted_content":%q},{"type":"message","role":"user","content":"next"}]}`, f.model, encrypted)
			f.business = f.success
			before := len(f.snapshot())
			f.requireStatus("wire-b", f.path, continuation, 200)
			writes := f.snapshot()[before:]
			if len(writes) != 1 || writes[0].account != signer || !strings.Contains(string(writes[0].body), encrypted) {
				t.Fatalf("continuation lost actual signer/block: %+v", writes)
			}
			foreign := fmt.Sprintf(`{"model":%q,"input":[{"type":"compaction","encrypted_content":"native-human-signed"}]}`, f.model)
			before = len(f.snapshot())
			status, _ := f.post("wire-a", f.path, foreign)
			if status < 400 || len(f.snapshot()) != before {
				t.Fatalf("foreign signer degraded/reselected: status=%d writes=%+v", status, f.snapshot()[before:])
			}
			a, _ := f.manager.GetByID(f.accounts[signer].id)
			a.Disabled = true
			if _, err := f.manager.Update(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			before = len(f.snapshot())
			status, _ = f.post("wire-a", f.path, continuation)
			if status < 400 || len(f.snapshot()) != before {
				t.Fatalf("excluded signer wrote alternate account: status=%d writes=%+v", status, f.snapshot()[before:])
			}
		})
	}
}

// A real native source's Body.Close is the deterministic terminal barrier. No
// fake StreamResult/Complete callback or executor counter substitutes for it.
func TestPoolNativeGatewayStreamCleanupCapacity(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, ending := range []string{"cancel", "eof", "bootstrap-503", "bootstrap-401"} {
			t.Run(provider+"/"+ending, func(t *testing.T) {
				f := newWireFixture(t, provider)
				gate := newWireCloseGate()
				defer gate.allow()
				first := true
				f.closeGate = func(r *http.Request, _ *http.Response) *wireCloseGate {
					if r.URL.Path == "/backend-api/codex/responses" || r.URL.Path == "/v1/messages" {
						if first {
							first = false
							return gate
						}
					}
					return nil
				}
				upstreamCanceled := make(chan struct{})
				firstBusiness := true
				f.business = func(w http.ResponseWriter, r *http.Request, a *wireAccount, b []byte) {
					if !firstBusiness {
						f.success(w, r, a, b)
						return
					}
					firstBusiness = false
					if ending == "bootstrap-503" || ending == "bootstrap-401" {
						status := 503
						if ending == "bootstrap-401" {
							status = 401
						}
						w.WriteHeader(status)
						fmt.Fprint(w, `{"error":{"message":"synthetic bootstrap"}}`)
						return
					}
					if ending == "eof" {
						f.success(w, r, a, b)
						return
					}
					if provider == "codex" {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprintf(w, "data: {\"type\":\"response.created\",\"response\":{\"id\":\"held\",\"model\":%q}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"held\"}\n\n", f.model)
					} else {
						w.Header().Set("Content-Type", "text/event-stream")
						fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"held\",\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n", f.model)
					}
					w.(http.Flusher).Flush()
					<-r.Context().Done()
					close(upstreamCanceled)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				rr := httptest.NewRecorder()
				flushed := make(chan struct{})
				writer := &wireFlushRecorder{ResponseRecorder: rr, flushed: flushed}
				done := make(chan struct{})
				go func() {
					defer close(done)
					f.server.Handler().ServeHTTP(writer, f.request(ctx, "wire-a", f.path, f.payload(true)))
				}()
				if ending == "cancel" {
					select {
					case <-flushed:
					case <-done:
						t.Fatalf("stream failed before bootstrap: %d %s", rr.Code, rr.Body.String())
					}
					cancel()
				}
				select {
				case <-gate.started:
				case <-done:
					t.Fatalf("stream never reached native cleanup: %d %s", rr.Code, rr.Body.String())
				}
				if ending == "cancel" {
					<-upstreamCanceled
				}
				before := len(f.snapshot())
				response := f.requireStatus("wire-b", f.path, f.payload(false), 429)
				if !strings.Contains(string(response), "api_key_pool_capacity") || len(f.snapshot()) != before {
					t.Fatal("capacity denial sent business request or lacked explicit error")
				}
				select {
				case <-done:
					t.Fatal("handler completed before native body cleanup")
				default:
				}
				gate.allow()
				<-done
				if ending != "cancel" && rr.Code != 200 {
					t.Fatalf("native stream/bootstrap retry=%d %s", rr.Code, rr.Body.String())
				}
				f.requireStatus("wire-b", f.path, f.payload(false), 200)
				writes := f.snapshot()
				for _, write := range writes {
					if write.account == "human" {
						t.Fatal("cleanup/retry borrowed human account")
					}
				}
				if ending == "bootstrap-503" && (len(writes) < 2 || writes[0].account == writes[1].account) {
					t.Fatalf("cleanup did not allow same-pool bootstrap retry: %+v", writes)
				}
				if ending == "bootstrap-401" && len(writes) < 2 {
					t.Fatalf("cleanup did not allow official-refresh bootstrap retry: %+v", writes)
				}
			})
		}
	}
}

type wireFlushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
	once    sync.Once
}

func (w *wireFlushRecorder) Flush() {
	w.ResponseRecorder.Flush()
	w.once.Do(func() { close(w.flushed) })
}

func TestPoolNativeGatewayOfficialIdentityFailures(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, failure := range []string{"missing-account", "missing-entitlement", "ambiguous", "changed"} {
			t.Run(provider+"/"+failure, func(t *testing.T) {
				f := newWireFixture(t, provider)
				var transitionHook *wireTransitionHook
				if failure == "changed" {
					logger := log.StandardLogger()
					previousHooks := logger.ReplaceHooks(make(log.LevelHooks))
					transitionHook = &wireTransitionHook{}
					logger.AddHook(transitionHook)
					t.Cleanup(func() { logger.ReplaceHooks(previousHooks) })
					f.requireStatus("wire-a", f.path, f.payload(false), 200)
				}
				f.identity = func(a *wireAccount) (string, string) {
					if a.name != "a" {
						return a.account, a.entitlement
					}
					switch failure {
					case "missing-account":
						return "", a.entitlement
					case "missing-entitlement":
						return a.account, ""
					case "ambiguous":
						return a.account, f.accounts["human"].entitlement
					default:
						return f.accounts["human"].account, f.accounts["human"].entitlement
					}
				}
				if failure == "changed" {
					// A proven agent credential that resolves to the human account is
					// quarantined from both pools; unchanged B and H remain usable.
					a, _ := f.manager.GetByID(f.accounts["a"].id)
					a.SetMetadata("access_token", f.accounts["a"].access+"-rotated")
					f.accounts["a"].access += "-rotated"
					if _, err := f.manager.Update(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					before := len(f.snapshot())
					status, response := f.post("wire-b", f.path, f.payload(false))
					writes := f.snapshot()[before:]
					if status != 200 || len(writes) != 1 || writes[0].account != "b" || strings.Contains(string(response), "error") {
						t.Fatalf("authorized new operation did not use unchanged B: status=%d body=%s writes=%+v", status, response, writes)
					}
					before = len(f.snapshot())
					status, _ = f.post("wire-a", f.path, f.payload(false))
					for _, write := range f.snapshot()[before:] {
						if write.account == "a" || write.account == "human" {
							t.Fatalf("quarantined A served a pool: status=%d write=%+v", status, write)
						}
					}
					if status != 200 {
						t.Fatalf("same-pool agent operation failed despite unchanged B: status=%d", status)
					}
					before = len(f.snapshot())
					if status, _ = f.post("wire-human", f.path, f.payload(false)); status != 200 {
						t.Fatalf("unchanged human control failed: status=%d", status)
					}
					writes = f.snapshot()[before:]
					if len(writes) != 1 || writes[0].account != "human" {
						t.Fatalf("human control wrote wrong account: %+v", writes)
					}
					if got := transitionHook.transitionCount("wire-a"); got != 1 {
						t.Fatalf("transition warning count=%d want=1", got)
					}
					return
				}
				before := len(f.snapshot())
				status, response := f.post("wire-b", f.path, f.payload(false))
				if status != 503 || len(f.snapshot()) != before {
					t.Fatalf("official %s identity allowed business: status=%d body=%s writes=%+v", failure, status, response, f.snapshot()[before:])
				}
				f.mu.Lock()
				control := codexauth.TokenURL
				if provider == "claude" {
					control = claudeauth.ProfileURL
				}
				calls := f.controls[control]
				f.mu.Unlock()
				if calls == 0 {
					t.Fatal("identity failure did not traverse official native acquisition")
				}
			})
		}
	}
}
