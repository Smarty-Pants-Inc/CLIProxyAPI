package helps

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type poolHTTPFixtureTransport struct {
	calls  int
	status int
	body   *poolHTTPFixtureBody
}

func (t *poolHTTPFixtureTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.calls++
	status := t.status
	if status == 0 {
		status = 200
	}
	body := t.body
	if body == nil {
		body = &poolHTTPFixtureBody{Reader: strings.NewReader(`{"ok":true}`)}
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: body}, nil
}

type poolHTTPFixtureBody struct {
	io.Reader
	closed bool
}

func (b *poolHTTPFixtureBody) Close() error { b.closed = true; return nil }

type poolHTTPFixtureExecutor struct {
	cfg      *config.Config
	base     *poolHTTPFixtureTransport
	mutate   func(*http.Request)
	provider string
}

func (e *poolHTTPFixtureExecutor) Identifier() string { return e.provider }
func (e *poolHTTPFixtureExecutor) AcquirePoolIdentity(_ context.Context, a *core.Auth) (*core.Auth, core.NativePoolIdentity, error) {
	i := core.NativePoolIdentity{Provider: e.provider, AccountID: "native-user", EntitlementID: "native-entitlement"}
	if e.provider == "claude" {
		i.AccountID = "11111111-1111-4111-8111-111111111111"
		i.EntitlementID = "22222222-2222-4222-8222-222222222222"
		a.SetMetadata("account_uuid", i.AccountID)
		a.SetMetadata("organization_uuid", i.EntitlementID)
	} else {
		a.SetMetadata("account_id", i.EntitlementID)
	}
	return a, i, nil
}
func (e *poolHTTPFixtureExecutor) Execute(ctx context.Context, a *core.Auth, r ex.Request, _ ex.Options) (ex.Response, error) {
	target := "https://chatgpt.com/backend-api/codex/responses"
	if e.provider == "claude" {
		target = "https://api.anthropic.com/v1/messages/count_tokens?beta=true"
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(r.Payload))
	req.Header.Set("Authorization", "Bearer "+a.MetadataString("access_token"))
	if e.provider == "codex" {
		req.Header.Set("Chatgpt-Account-Id", a.MetadataString("account_id"))
	}
	if e.mutate != nil {
		e.mutate(req)
	}
	// No usage reporter is involved. This is the real factory fence around a
	// deterministic local transport; even a guard regression cannot call a provider.
	client := fenceNativePoolClient(ctx, e.cfg, &http.Client{Transport: e.base})
	resp, err := client.Do(req)
	if err != nil {
		return ex.Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return ex.Response{Payload: body}, err
}
func (e *poolHTTPFixtureExecutor) CountTokens(ctx context.Context, a *core.Auth, r ex.Request, o ex.Options) (ex.Response, error) {
	return e.Execute(ctx, a, r, o)
}
func (*poolHTTPFixtureExecutor) ExecuteStream(context.Context, *core.Auth, ex.Request, ex.Options) (*ex.StreamResult, error) {
	return nil, errors.New("unused fixture stream")
}
func (*poolHTTPFixtureExecutor) Refresh(context.Context, *core.Auth) (*core.Auth, error) {
	return nil, errors.New("generic refresh not permitted")
}
func (*poolHTTPFixtureExecutor) HttpRequest(context.Context, *core.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("raw send not permitted")
}

func poolHTTPFixture(t *testing.T, provider string) (*core.Manager, *poolHTTPFixtureExecutor) {
	t.Helper()
	account, entitlement := "native-user", "native-entitlement"
	if provider == "claude" {
		account = "11111111-1111-4111-8111-111111111111"
		entitlement = "22222222-2222-4222-8222-222222222222"
	}
	raw := fmt.Sprintf(`ws-auth: true
access:
  api-keys: ["factory-key"]
  account-pools:
    - id: agents
      org: test
      class: agent
      max-in-flight: 1
      accounts:
        - {provider: %s, account-id: %s, entitlement-id: %s}
  api-key-policies:
    - {key-sha256: "%x", pool: agents}
`, provider, account, entitlement, sha256.Sum256([]byte("factory-key")))
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	m := core.NewManager(nil, nil, nil)
	m.SetConfig(cfg)
	e := &poolHTTPFixtureExecutor{cfg: cfg, provider: provider, base: &poolHTTPFixtureTransport{}}
	if err = m.RegisterNativePoolExecutor(e); err != nil {
		t.Fatal(err)
	}
	id := t.Name()
	_, err = m.Register(context.Background(), &core.Auth{ID: id, Provider: provider, Status: core.StatusActive, Attributes: map[string]string{"auth_kind": "oauth"}, Metadata: map[string]any{"access_token": "fake-native-access", "refresh_token": "fake-native-refresh"}})
	if err != nil {
		t.Fatal(err)
	}
	registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: "factory-model"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	return m, e
}
func poolHTTPStatus(err error) int {
	var v interface{ StatusCode() int }
	if errors.As(err, &v) {
		return v.StatusCode()
	}
	return 0
}

func TestPoolNativeFactoryFinalMutationsAndCountWithoutReporter(t *testing.T) {
	for _, provider := range []string{"codex", "claude"} {
		for _, scenario := range []string{"valid", "account-header", "authorization-case", "wrong-model", "wrong-origin", "query", "redirect"} {
			t.Run(provider+"/"+scenario, func(t *testing.T) {
				m, e := poolHTTPFixture(t, provider)
				kind := core.PoolResponses
				if provider == "claude" {
					kind = core.PoolCountTokens
				}
				e.mutate = func(r *http.Request) {
					switch scenario {
					case "account-header":
						r.Header.Set("Chatgpt-Account-Id", "foreign-entitlement")
					case "authorization-case":
						r.Header["authorization"] = []string{"Bearer forged"}
					case "wrong-model":
						r.Body = io.NopCloser(strings.NewReader(`{"model":"forbidden-model"}`))
					case "wrong-origin":
						r.URL.Host = "foreign.invalid"
						r.Host = r.URL.Host
					case "query":
						r.URL.RawQuery = "beta=true&account=foreign"
					}
				}
				if scenario == "redirect" {
					e.base.status = 307
					e.base.body = &poolHTTPFixtureBody{Reader: strings.NewReader("")}
				}
				ctx, op, err := m.BeginPoolOperation(context.Background(), "factory-key", "factory-model", kind)
				if err != nil {
					t.Fatal(err)
				}
				defer op.Finish()
				req := ex.Request{Model: "factory-model", Payload: []byte(`{"model":"factory-model"}`)}
				if provider == "claude" {
					_, err = m.ExecuteCount(ctx, []string{provider}, req, ex.Options{})
				} else {
					_, err = m.Execute(ctx, []string{provider}, req, ex.Options{})
				}
				if scenario == "valid" {
					if err != nil || e.base.calls != 1 {
						t.Fatalf("valid request err=%v calls=%d", err, e.base.calls)
					}
					return
				}
				if err == nil {
					t.Fatal("final native mutation was accepted")
				}
				wantCalls := 0
				if scenario == "redirect" {
					wantCalls = 1
					if !e.base.body.closed {
						t.Fatal("redirect body not closed")
					}
				}
				if e.base.calls != wantCalls {
					t.Fatalf("calls=%d, want %d; err=%v", e.base.calls, wantCalls, err)
				}
				if scenario == "wrong-model" && poolHTTPStatus(err) != 403 {
					t.Fatalf("model denial=%v", err)
				}
			})
		}
	}
}

func TestPoolFactoryMissingAdmissionAndLegacyControl(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			cfg := &config.Config{}
			if enabled {
				empty := []config.AccountPool{}
				cfg.AccountPools = &empty
			}
			base := &poolHTTPFixtureTransport{}
			client := fenceNativePoolClient(context.Background(), cfg, &http.Client{Transport: base})
			req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages/count_tokens?beta=true", strings.NewReader(`{"model":"factory-model"}`))
			resp, err := client.Do(req)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			if enabled {
				if err == nil || base.calls != 0 {
					t.Fatalf("missing admission sent: err=%v calls=%d", err, base.calls)
				}
			} else if err != nil || base.calls != 1 {
				t.Fatalf("legacy behavior changed: err=%v calls=%d", err, base.calls)
			}
		})
	}
}

func TestPoolOfficialAcquisitionEndpointAndRedirectFence(t *testing.T) {
	for _, scenario := range []string{"token", "business", "alternate", "redirect"} {
		t.Run(scenario, func(t *testing.T) {
			base := &poolHTTPFixtureTransport{}
			target := "https://auth.openai.com/oauth/token"
			if scenario == "business" {
				target = "https://chatgpt.com/backend-api/codex/responses"
			}
			if scenario == "alternate" {
				target = "https://foreign.invalid/oauth/token"
			}
			if scenario == "redirect" {
				base.status = 302
				base.body = &poolHTTPFixtureBody{Reader: strings.NewReader("")}
			}
			req, _ := http.NewRequest("POST", target, strings.NewReader(`{}`))
			_, err := (poolAcquisitionTransport{base: base, provider: "codex"}).RoundTrip(req)
			if scenario == "token" {
				if err != nil || base.calls != 1 {
					t.Fatalf("token path denied: %v", err)
				}
			} else if err == nil {
				t.Fatal("unsafe acquisition accepted")
			}
			if (scenario == "business" || scenario == "alternate") && base.calls != 0 {
				t.Fatal("credentials reached non-native service")
			}
			if scenario == "redirect" && !base.body.closed {
				t.Fatal("acquisition redirect body not closed")
			}
		})
	}
}
