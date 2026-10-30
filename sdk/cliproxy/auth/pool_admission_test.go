package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

const poolAdmissionModel = "pool-admission-model"
const poolAdmissionPayload = `{"model":"pool-admission-model","input":"test"}`
const poolAdmissionReply = `{"output":"pool-admission-ok"}`
const poolAdmissionURL = "https://pool-admission.invalid/v1/responses"

// Keep reason: the public SDK is a trust boundary independent of Gin. Pool mode
// must reject missing Manager admission before selection, preparation or sends.
// These use only base APIs: raw YAML is intentionally ignored by the old binary,
// so its real execution paths reach the fake instead of failing to compile.
func TestPoolAdmissionRequiredWithoutHTTPContext(t *testing.T) {
	tests := []struct {
		name     string
		wantCall string // Positive control: the no-pools path actually reaches this hook.
		run      func(*testing.T, context.Context, *poolAdmissionFixture) (bool, error)
	}{
		{"Execute", "Execute", func(_ *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			resp, err := f.manager.Execute(ctx, []string{"codex"}, poolAdmissionRequest(), ex.Options{})
			return string(resp.Payload) == poolAdmissionReply, err
		}},
		{"ExecuteCount", "CountTokens", func(_ *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			resp, err := f.manager.ExecuteCount(ctx, []string{"codex"}, poolAdmissionRequest(), ex.Options{})
			return string(resp.Payload) == poolAdmissionReply, err
		}},
		{"ExecuteStream", "ExecuteStream", func(t *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			result, err := f.manager.ExecuteStream(ctx, []string{"codex"}, poolAdmissionRequest(), ex.Options{Stream: true})
			if result == nil {
				return false, err
			}
			if result.Chunks == nil {
				t.Fatal("stream returned without a source")
			}
			var payload strings.Builder
			for chunk := range result.Chunks {
				payload.Write(chunk.Payload)
				if chunk.Err != nil {
					err = chunk.Err
				}
			}
			return payload.String() == poolAdmissionReply, err
		}},
		{"HttpRequest", "upstream", func(t *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			resp, err := f.manager.HttpRequest(ctx, f.auth, poolAdmissionHTTPRequest(t, ctx))
			if resp == nil {
				return false, err
			}
			defer func() {
				if errClose := resp.Body.Close(); errClose != nil {
					t.Errorf("close fake response: %v", errClose)
				}
			}()
			body, errRead := io.ReadAll(resp.Body)
			if errRead != nil {
				t.Fatalf("read fake response: %v", errRead)
			}
			return string(body) == poolAdmissionReply, err
		}},
		{"SelectAuth", "", func(_ *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			selected, err := f.manager.SelectAuth(ctx, "codex", poolAdmissionModel, ex.Options{})
			return selected != nil, err
		}},
		{"SelectAuthByKind", "", func(_ *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			selected, err := f.manager.SelectAuthByKind(ctx, "codex", poolAdmissionModel, "oauth", ex.Options{})
			return selected != nil, err
		}},
		{"InjectCredentials", "PrepareRequest", func(t *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			req := poolAdmissionHTTPRequest(t, ctx)
			err := f.manager.InjectCredentials(req, f.auth.ID)
			return req.Header.Get("Authorization") != "", err
		}},
		{"PrepareHttpRequest", "PrepareRequest", func(t *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			req := poolAdmissionHTTPRequest(t, ctx)
			err := f.manager.PrepareHttpRequest(ctx, f.auth, req)
			return req.Header.Get("Authorization") != "", err
		}},
		{"NewHttpRequest", "PrepareRequest", func(_ *testing.T, ctx context.Context, f *poolAdmissionFixture) (bool, error) {
			req, err := f.manager.NewHttpRequest(ctx, f.auth, http.MethodPost, poolAdmissionURL, []byte(poolAdmissionPayload), nil)
			return req != nil, err
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, pooled := range []bool{false, true} {
				mode := "no-pools"
				if pooled {
					mode = "pools"
				}
				t.Run(mode, func(t *testing.T) {
					f := newPoolAdmissionFixture(t, pooled)
					// Deliberately no Gin, principal, policy context or admission.
					usable, err := tc.run(t, context.Background(), f)
					calls := f.executor.callsSnapshot()
					if !pooled {
						if err != nil || !usable {
							t.Fatalf("no-pools SDK path must remain usable: usable=%v err=%v calls=%v", usable, err, calls)
						}
						if tc.wantCall != "" && !slices.Contains(calls, tc.wantCall) {
							t.Fatalf("positive control did not reach %s: calls=%v", tc.wantCall, calls)
						}
						return
					}
					// Check side effects even when the denial is missing/wrong, so
					// the base failure records actual unwanted fake invocations.
					if len(calls) != 0 {
						t.Errorf("pool admission bypass: fake side effects before admission: %v", calls)
					}
					if usable {
						t.Error("pool admission bypass: SDK returned a usable response, credential or request")
					}
					var status interface{ StatusCode() int }
					if !errors.As(err, &status) || status.StatusCode() != http.StatusServiceUnavailable {
						t.Errorf("missing admission must return 503 api_key_pool_admission_required: err=%v", err)
					} else if !strings.Contains(err.Error(), "api_key_pool_admission_required") && !strings.Contains(err.Error(), "api_key_policy_unavailable") {
						// The existing safe policy-unavailable denial is also supported;
						// unrelated model/identity/executor errors are not this gate.
						t.Errorf("503 must identify missing admission/policy: %v", err)
					}
				})
			}
		})
	}
}

type poolAdmissionFixture struct {
	manager  *Manager
	auth     *Auth
	executor *poolAdmissionExecutor
}

func newPoolAdmissionFixture(t *testing.T, pooled bool) *poolAdmissionFixture {
	t.Helper()
	// Both keys are fully covered. Neither pool is full/zero, no model is
	// forbidden, and human live relay is enabled. Missing admission must win
	// before native identity acquisition; this fake has no native proof API.
	raw := `ws-auth: true
codex:
  live-media-relay:
    enabled: true
access:
  api-keys: ["pool-test-human-key", "pool-test-agent-key"]
`
	if pooled {
		raw += fmt.Sprintf(`  account-pools:
    - id: test-human
      org: test-org
      class: human
      max-in-flight: 2
      accounts:
        - provider: codex
          account-id: test-human-user
          entitlement-id: test-human-entitlement
    - id: test-agent
      org: test-org
      class: agent
      max-in-flight: 2
      accounts:
        - provider: claude
          account-id: "11111111-1111-4111-8111-111111111111"
          entitlement-id: "22222222-2222-4222-8222-222222222222"
  api-key-policies:
    - key-sha256: "%x"
      pool: test-human
    - key-sha256: "%x"
      pool: test-agent
`, sha256.Sum256([]byte("pool-test-human-key")), sha256.Sum256([]byte("pool-test-agent-key")))
	}
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatalf("parse valid %v pool fixture: %v", pooled, err)
	}
	manager := NewManager(nil, nil, nil)
	manager.SetConfig(cfg)
	executor := &poolAdmissionExecutor{}
	manager.RegisterExecutor(executor)
	auth, err := manager.Register(context.Background(), &Auth{
		ID: t.Name(), Provider: "codex", Status: StatusActive,
		Attributes: map[string]string{"auth_kind": "oauth"},
		Metadata:   map[string]any{"access_token": "synthetic-test-token", "refresh_token": "synthetic-test-refresh"},
	})
	if err != nil {
		t.Fatalf("register synthetic auth: %v", err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: poolAdmissionModel}})
	t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
	return &poolAdmissionFixture{manager: manager, auth: auth, executor: executor}
}

func poolAdmissionRequest() ex.Request {
	return ex.Request{Model: poolAdmissionModel, Payload: []byte(poolAdmissionPayload)}
}

func poolAdmissionHTTPRequest(t *testing.T, ctx context.Context) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, poolAdmissionURL, strings.NewReader(poolAdmissionPayload))
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// Implements only existing executor/preparer/transport contracts, all in memory.
// No native identity acquisition, policy minting, real client or network is used.
type poolAdmissionExecutor struct {
	mu    sync.Mutex
	calls []string
}

var (
	_ ProviderExecutor    = (*poolAdmissionExecutor)(nil)
	_ RequestAuthPreparer = (*poolAdmissionExecutor)(nil)
	_ RequestPreparer     = (*poolAdmissionExecutor)(nil)
	_ http.RoundTripper   = (*poolAdmissionExecutor)(nil)
)

func (*poolAdmissionExecutor) Identifier() string { return "codex" }
func (e *poolAdmissionExecutor) record(call string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls = append(e.calls, call)
}
func (e *poolAdmissionExecutor) callsSnapshot() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}
func (e *poolAdmissionExecutor) ShouldPrepareRequestAuth(*Auth) bool {
	e.record("ShouldPrepareRequestAuth")
	return true
}
func (e *poolAdmissionExecutor) PrepareRequestAuth(_ context.Context, auth *Auth) (*Auth, error) {
	e.record("PrepareRequestAuth")
	return auth.Clone(), nil
}
func (e *poolAdmissionExecutor) PrepareRequest(req *http.Request, auth *Auth) error {
	e.record("PrepareRequest")
	req.Header.Set("Authorization", "Bearer "+auth.MetadataString("access_token"))
	return nil
}
func (e *poolAdmissionExecutor) Execute(context.Context, *Auth, ex.Request, ex.Options) (ex.Response, error) {
	e.record("Execute")
	return ex.Response{Payload: []byte(poolAdmissionReply)}, nil
}
func (e *poolAdmissionExecutor) CountTokens(context.Context, *Auth, ex.Request, ex.Options) (ex.Response, error) {
	e.record("CountTokens")
	return ex.Response{Payload: []byte(poolAdmissionReply)}, nil
}
func (e *poolAdmissionExecutor) ExecuteStream(context.Context, *Auth, ex.Request, ex.Options) (*ex.StreamResult, error) {
	e.record("ExecuteStream")
	chunks := make(chan ex.StreamChunk, 1)
	chunks <- ex.StreamChunk{Payload: []byte(poolAdmissionReply)}
	close(chunks)
	return &ex.StreamResult{Chunks: chunks}, nil
}
func (e *poolAdmissionExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.record("Refresh")
	return auth.Clone(), nil
}
func (e *poolAdmissionExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	e.record("HttpRequest")
	if errPrepare := e.PrepareRequest(req, auth); errPrepare != nil {
		return nil, errPrepare
	}
	return e.RoundTrip(req.WithContext(ctx))
}
func (e *poolAdmissionExecutor) RoundTrip(req *http.Request) (*http.Response, error) {
	e.record("upstream")
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(poolAdmissionReply)), Request: req}, nil
}
