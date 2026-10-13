package codex

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOAuthServerExpectedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		query  string
		status int
		want   OAuthResult
	}{
		{"success", "code=valid-code&state=expected", http.StatusFound, OAuthResult{Code: "valid-code", State: "expected"}},
		{"provider error", "error=access_denied&state=expected", http.StatusBadRequest, OAuthResult{Error: "access_denied"}},
		{"matching state without code", "state=expected", http.StatusBadRequest, OAuthResult{Error: "no_code"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewOAuthServer(0)
			s.SetExpectedState("expected")
			type outcome struct {
				result *OAuthResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := s.WaitForCallback(time.Second)
				done <- outcome{result, err}
			}()

			for _, query := range []string{
				"", "unrelated=value", "code=unrelated", "state=wrong",
				"code=unrelated&state=wrong", "code=unrelated&state=%",
				"error=access_denied", "error=access_denied&state=wrong",
			} {
				w := httptest.NewRecorder()
				s.handleCallback(w, httptest.NewRequest(http.MethodGet, "/auth/callback?"+query, nil))
				if w.Code != http.StatusNotFound {
					t.Fatalf("query %q: status = %d, want 404", query, w.Code)
				}
				if len(s.resultChan) != 0 {
					t.Fatalf("query %q: rejected callback queued a result", query)
				}
				select {
				case got := <-done:
					t.Fatalf("query %q ended WaitForCallback: %+v", query, got)
				default:
				}
			}

			w := httptest.NewRecorder()
			s.handleCallback(w, httptest.NewRequest(http.MethodGet, "/auth/callback?"+tc.query, nil))
			if w.Code != tc.status {
				t.Fatalf("matching callback status = %d, want %d", w.Code, tc.status)
			}
			got := <-done
			if got.err != nil || got.result == nil || *got.result != tc.want {
				t.Fatalf("WaitForCallback = (%+v, %v), want %+v", got.result, got.err, tc.want)
			}
		})
	}
}

func TestOAuthServerWithoutExpectedState(t *testing.T) {
	for _, tc := range []struct {
		query  string
		status int
		want   OAuthResult
	}{
		{"code=valid-code&state=any", http.StatusFound, OAuthResult{Code: "valid-code", State: "any"}},
		{"error=access_denied", http.StatusBadRequest, OAuthResult{Error: "access_denied"}},
		{"", http.StatusBadRequest, OAuthResult{Error: "no_code"}},
		{"code=valid-code", http.StatusBadRequest, OAuthResult{Error: "no_state"}},
	} {
		t.Run(tc.query, func(t *testing.T) {
			s := NewOAuthServer(0)
			w := httptest.NewRecorder()
			s.handleCallback(w, httptest.NewRequest(http.MethodGet, "/auth/callback?"+tc.query, nil))
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			got, err := s.WaitForCallback(time.Second)
			if err != nil || got == nil || *got != tc.want {
				t.Fatalf("WaitForCallback = (%+v, %v), want %+v", got, err, tc.want)
			}
		})
	}
}

func TestOAuthServerListensOnLoopback(t *testing.T) {
	// Keep another loopback address on the same port occupied. A wildcard
	// port check or listener would conflict with it; 127.0.0.1 must not.
	other, err := net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close() })
	port := other.Addr().(*net.TCPAddr).Port
	s := NewOAuthServer(port)
	s.SetExpectedState("expected")
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Stop(context.Background()); err != nil {
			t.Error(err)
		}
	})
	wantAddr := fmt.Sprintf("127.0.0.1:%d", port)
	if s.server.Addr != wantAddr {
		t.Fatalf("listener address = %q, want %q", s.server.Addr, wantAddr)
	}
	client := &http.Client{
		Timeout:       time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(client.CloseIdleConnections)
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"error=access_denied&state=wrong", http.StatusNotFound},
		{"code=valid-code&state=expected", http.StatusFound},
	} {
		resp, err := client.Get("http://" + wantAddr + "/auth/callback?" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("query %q: status = %d, want %d", tc.query, resp.StatusCode, tc.status)
		}
	}
	got, err := s.WaitForCallback(time.Second)
	if err != nil || got == nil || got.Code != "valid-code" || got.State != "expected" {
		t.Fatalf("loopback callback = (%+v, %v)", got, err)
	}
}
