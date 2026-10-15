package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

const reservationPayload = `{"model":"reservation-model","max_output_tokens":32,"input":"hello"}`

// Exercise the last policy fence and a real HTTP transport, not only admission.
func reservationManager(t *testing.T, cap int64) (*Manager, []config.APIKeyPolicy, *httptest.Server, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != reservationPayload {
			t.Errorf("wire payload=%s err=%v", body, err)
		}
		_, _ = w.Write([]byte("upstream reply"))
	}))
	t.Cleanup(upstream.Close)
	m := NewManager(nil, nil, nil)
	p := []config.APIKeyPolicy{{KeySHA256: keyDigest(t.Name()), AllowedAuths: []string{"reservation-auth"}, DailyTokenCap: policyInt(cap)}}
	m.SetConfig(&config.Config{})
	_, err := m.Register(context.Background(), &Auth{ID: "reservation-auth", Provider: "codex", Status: StatusActive, Attributes: map[string]string{"api_key": "test-token"}})
	if err != nil {
		t.Fatal(err)
	}
	m.RegisterExecutor(&countingRefreshExecutor{id: "codex"})
	registry.GetGlobalRegistry().RegisterClient("reservation-auth", "codex", []*registry.ModelInfo{{ID: "reservation-model", MaxCompletionTokens: 128}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("reservation-auth") })
	return m, p, upstream, calls
}

func reservationSend(ctx context.Context, m *Manager, upstream *httptest.Server) error {
	op := KeyPolicyFromContext(ctx)
	if _, _, err := op.selectExecutor(ex.Request{Model: "reservation-model"}, ex.Options{}); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, strings.NewReader(reservationPayload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer test-token")
	if err = CheckKeyPolicySend(req); err != nil {
		return err
	}
	resp, err := upstream.Client().Do(req)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if string(body) != "upstream reply" {
		return errors.New("missing upstream response")
	}
	return nil
}

func reservationAttempt(m *Manager, p []config.APIKeyPolicy, upstream *httptest.Server, actual int64, failed bool) error {
	ctx, done, err := m.BeginKeyPolicy(context.Background(), p, "reservation-model")
	if err != nil {
		return err
	}
	defer done()
	if err = reservationSend(ctx, m, upstream); err != nil {
		return err
	}
	usage.PublishRecord(ctx, usage.Record{Failed: failed, Detail: usage.Detail{InputTokens: actual}})
	return nil
}

func requireTokenRefusal(t *testing.T, err error) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.StatusCode() != 429 {
		t.Fatalf("want typed token refusal, got %v", err)
	}
}

func TestKeyPolicyDailyReservation(t *testing.T) {
	bound := int64(len(reservationPayload)) + 32
	t.Run("insufficient allowance never sends", func(t *testing.T) {
		m, p, upstream, calls := reservationManager(t, bound-1)
		requireTokenRefusal(t, reservationAttempt(m, p, upstream, 7, false))
		if calls.Load() != 0 {
			t.Fatalf("upstream calls=%d", calls.Load())
		}
	})
	t.Run("exact fit settles actual", func(t *testing.T) {
		m, p, upstream, calls := reservationManager(t, bound+7)
		if err := reservationAttempt(m, p, upstream, 7, false); err != nil {
			t.Fatal(err)
		}
		if err := reservationAttempt(m, p, upstream, 7, false); err != nil {
			t.Fatalf("reservation not replaced by actual: %v", err)
		}
		requireTokenRefusal(t, reservationAttempt(m, p, upstream, 7, false))
		if calls.Load() != 2 {
			t.Fatalf("upstream calls=%d want 2", calls.Load())
		}
		if got := m.keyPolicyAccounts[p[0].KeySHA256].tokens; got != 14 {
			t.Fatalf("charged=%d want 14", got)
		}
	})
	t.Run("concurrent bounds cannot overspend", func(t *testing.T) {
		m, p, upstream, calls := reservationManager(t, bound+6)
		ctx, done, err := m.BeginKeyPolicy(context.Background(), p, "reservation-model")
		if err != nil {
			t.Fatal(err)
		}
		defer done()
		if err = reservationSend(ctx, m, upstream); err != nil {
			t.Fatal(err)
		}
		next := make(chan error, 1)
		started := make(chan struct{})
		go func() { close(started); next <- reservationAttempt(m, p, upstream, 7, false) }()
		<-started
		usage.PublishRecord(ctx, usage.Record{Detail: usage.Detail{InputTokens: 7}})
		done()
		requireTokenRefusal(t, <-next)
		if calls.Load() != 1 {
			t.Fatalf("upstream calls=%d want 1", calls.Load())
		}
	})
	t.Run("upstream error releases", func(t *testing.T) {
		m, p, upstream, calls := reservationManager(t, bound)
		if err := reservationAttempt(m, p, upstream, 0, true); err != nil {
			t.Fatal(err)
		}
		if err := reservationAttempt(m, p, upstream, 7, false); err != nil {
			t.Fatalf("failed call retained reservation: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("upstream calls=%d want 2", calls.Load())
		}
		if got := m.keyPolicyAccounts[p[0].KeySHA256].tokens; got != 7 {
			t.Fatalf("charged=%d want 7", got)
		}
	})
}

func TestKeyPolicyTokenBound(t *testing.T) {
	registry.GetGlobalRegistry().RegisterClient("bound-models", "codex", []*registry.ModelInfo{
		{ID: "bound-model", MaxCompletionTokens: 128, ContextLength: 4096},
		{ID: "bound-output-limit", OutputTokenLimit: 256},
	})
	defer registry.GetGlobalRegistry().UnregisterClient("bound-models")
	for _, tc := range []struct {
		name, body, model string
		output            int64
		opaque            bool
		unknown           bool
	}{
		{name: "max tokens", body: `{"max_tokens":16}`, output: 16},
		{name: "max output tokens", body: `{"max_output_tokens":32}`, output: 32},
		{name: "max completion tokens", body: `{"max_completion_tokens":64}`, output: 64},
		{name: "largest alias", body: `{"max_tokens":16,"max_output_tokens":64,"max_completion_tokens":32}`, output: 64},
		{name: "registry ceiling", body: `{}`, output: 128},
		{name: "registry output limit", body: `{}`, model: "bound-output-limit", output: 256},
		{name: "missing ceiling", body: `{}`, model: "unknown-bound-model", unknown: true},
		{name: "bad json", body: `{`, unknown: true},
		{name: "null limit", body: `{"max_tokens":null}`, unknown: true},
		{name: "string limit", body: `{"max_tokens":"1"}`, unknown: true},
		{name: "zero limit", body: `{"max_tokens":0}`, unknown: true},
		{name: "negative limit", body: `{"max_tokens":-1}`, unknown: true},
		{name: "fractional limit", body: `{"max_tokens":1.5}`, unknown: true},
		{name: "limit overflow", body: `{"max_tokens":9223372036854775808}`, unknown: true},
		{name: "sum overflow", body: `{"max_tokens":9223372036854775807}`, unknown: true},
		{name: "multiple candidates", body: `{"max_tokens":16,"n":3}`, output: 48},
		{name: "best of", body: `{"max_tokens":16,"n":2,"best_of":3}`, output: 48},
		{name: "candidate overflow", body: `{"max_tokens":9223372036854775807,"n":2}`, unknown: true},
		{name: "media input", body: `{"max_tokens":16,"messages":[{"content":[{"type":"image","source":{"type":"url","url":"https://example.test/image"}}]}]}`, output: 16, opaque: true},
		{name: "encrypted input", body: `{"max_tokens":16,"input":[{"encrypted_content":"small"}]}`, output: 16, opaque: true},
		{name: "server conversation", body: `{"max_tokens":16,"previous_response_id":"prior"}`, output: 16, opaque: true},
		{name: "server retrieval", body: `{"max_tokens":16,"tools":[{"type":"web_search_20250305"}]}`, output: 16, opaque: true},
		{name: "media unknown context", body: `{"max_tokens":16,"input":[{"type":"input_image"}]}`, model: "bound-output-limit", unknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			model := tc.model
			if model == "" {
				model = "bound-model"
			}
			want := int64(len(tc.body)) + tc.output
			if tc.opaque {
				want = 4096 + tc.output
			}
			if tc.unknown {
				want = keyPolicyUnknownTokenBound
			}
			if got := keyPolicyTokenBound([]byte(tc.body), model, "codex"); got != want {
				t.Fatalf("bound=%d want=%d", got, want)
			}
		})
	}
}

func TestKeyPolicyReservationSettlement(t *testing.T) {
	bound := int64(len(reservationPayload)) + 32
	for _, outcome := range []string{"success", "failure", "partial failure", "cancel", "cancel without usage", "UTC rollover"} {
		t.Run(outcome, func(t *testing.T) {
			m, p, upstream, _ := reservationManager(t, bound+7)
			now := time.Date(2026, 10, 1, 23, 59, 59, 0, time.UTC)
			m.keyPolicyNow = func() time.Time { return now }
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx, done, err := m.BeginKeyPolicy(parent, p, "reservation-model")
			if err != nil {
				t.Fatal(err)
			}
			defer done()
			if err = reservationSend(ctx, m, upstream); err != nil {
				t.Fatal(err)
			}
			account := m.keyPolicyAccounts[p[0].KeySHA256]
			if account.reserved != bound || account.tokens != 0 {
				t.Fatalf("before usage: reserved=%d tokens=%d", account.reserved, account.tokens)
			}
			failed := outcome == "failure" || outcome == "partial failure"
			partial := outcome == "partial failure" || outcome == "cancel"
			wantTokens, wantRequests := int64(7), int64(1)
			if outcome == "cancel without usage" {
				wantTokens = 0
			} else {
				usage.PublishRecord(ctx, usage.Record{Failed: failed, Detail: usage.Detail{InputTokens: 4, Incomplete: partial}})
				usage.PublishRecord(ctx, usage.Record{Failed: failed, Detail: usage.Detail{InputTokens: 7, Incomplete: partial}})
				usage.PublishRecord(ctx, usage.Record{Detail: usage.Detail{InputTokens: 4, Incomplete: partial}})
			}
			if outcome == "cancel" || outcome == "cancel without usage" {
				cancel()
			}
			if outcome == "UTC rollover" {
				now = now.Add(time.Second)
				wantRequests = 0
			}
			done()
			done()
			usage.PublishRecord(ctx, usage.Record{Detail: usage.Detail{InputTokens: 100}})
			if account.reserved != 0 || account.tokens != wantTokens || account.requests != wantRequests {
				t.Fatalf("after settlement: reserved=%d tokens=%d requests=%d", account.reserved, account.tokens, account.requests)
			}
		})
	}
}
