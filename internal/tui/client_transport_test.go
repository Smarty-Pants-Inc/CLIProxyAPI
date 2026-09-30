package tui

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// routeAll sends every dial to one of two local test servers (port 443 to the
// TLS server, anything else to the plaintext one) and records the dialed
// addresses. It stands in for remote DNS.
func routeAll(c *Client, plain, tlsSrv *httptest.Server) func() []string {
	var mu sync.Mutex
	var dialed []string
	c.http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only local TLS server
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, addr)
			mu.Unlock()
			target := plain.Listener.Addr().String()
			if strings.HasSuffix(addr, ":443") {
				target = tlsSrv.Listener.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, target)
		},
	}
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), dialed...)
	}
}

// Security review CLIProxyAPI#21 R1: the remote TUI must never send the
// management key in plaintext off the host.
func TestClient_ManagementKeyNeverSentOverRemotePlainHTTP(t *testing.T) {
	var mu sync.Mutex
	var plainAuth []string
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		plainAuth = append(plainAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write([]byte(`{"status":"plain"}`))
	}))
	defer plain.Close()
	var tlsAuth string
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("downgrade") != "" {
			http.Redirect(w, r, "http://proxy.example.com/v0/management/config", http.StatusFound)
			return
		}
		tlsAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"tls"}`))
	}))
	defer tlsSrv.Close()

	t.Run("schemeless remote goes to https", func(t *testing.T) {
		c := NewClientWithBaseURL("proxy.example.com", "k-schemeless")
		dialed := routeAll(c, plain, tlsSrv)
		cfg, err := c.GetConfig()
		if err != nil || cfg["status"] != "tls" || tlsAuth != "Bearer k-schemeless" {
			t.Fatalf("cfg=%v err=%v tlsAuth=%q dialed=%v", cfg, err, tlsAuth, dialed())
		}
	})
	t.Run("explicit https works", func(t *testing.T) {
		c := NewClientWithBaseURL("https://proxy.example.com", "k-https")
		routeAll(c, plain, tlsSrv)
		cfg, err := c.GetConfig()
		if err != nil || cfg["status"] != "tls" || tlsAuth != "Bearer k-https" {
			t.Fatalf("cfg=%v err=%v tlsAuth=%q", cfg, err, tlsAuth)
		}
	})
	t.Run("explicit remote http is refused before any dial", func(t *testing.T) {
		c := NewClientWithBaseURL("http://proxy.example.com:8317", "k-plain")
		dialed := routeAll(c, plain, tlsSrv)
		if _, err := c.GetConfig(); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("remote plain HTTP was not refused: err=%v", err)
		}
		if got := dialed(); len(got) != 0 {
			t.Fatalf("dialed %v before refusing", got)
		}
		if err := RunWithBaseURL("http://proxy.example.com:8317", "k-plain", nil, nil); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("RunWithBaseURL accepted a remote plain-HTTP management URL: %v", err)
		}
	})
	t.Run("https to http redirect is refused", func(t *testing.T) {
		c := NewClientWithBaseURL("https://proxy.example.com", "k-redirect")
		routeAll(c, plain, tlsSrv)
		if _, err := c.get("/v0/management/config?downgrade=1"); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("downgrade redirect was not refused: err=%v", err)
		}
	})
	t.Run("loopback http still works", func(t *testing.T) {
		c := NewClientWithBaseURL(plain.URL, "k-local")
		cfg, err := c.GetConfig()
		if err != nil || cfg["status"] != "plain" {
			t.Fatalf("cfg=%v err=%v", cfg, err)
		}
	})
	mu.Lock()
	defer mu.Unlock()
	for _, got := range plainAuth {
		if got != "Bearer k-local" {
			t.Fatalf("plaintext server received a remote credential: %q", got)
		}
	}
}
