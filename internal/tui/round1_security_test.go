package tui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRound1ManagementTransport(t *testing.T) {
	if got := NewClientWithBaseURL("proxy.example.com:9000", "key").BaseURL(); got != "https://proxy.example.com:9000" {
		t.Errorf("implicit remote URL = %s", got)
	}
	c := NewClientWithBaseURL("http://192.0.2.1:8317", "key")
	c.http.Transport = round1Transport(func(r *http.Request) (*http.Response, error) {
		t.Error("remote plaintext credential reached transport")
		return nil, http.ErrNotSupported
	})
	if _, err := c.GetConfig(); err == nil {
		t.Error("plaintext accepted")
	}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/config", http.StatusFound)
	}))
	defer remote.Close()
	c = NewClientWithBaseURL(remote.URL, "key")
	c.http.Transport = remote.Client().Transport
	if _, err := c.GetConfig(); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Errorf("actual HTTPS redirect not rejected: %v", err)
	}
	if c.http.CheckRedirect == nil {
		t.Error("missing redirect validation")
	} else {
		req, _ := http.NewRequest("GET", "http://127.0.0.1:1/config", nil)
		previous, _ := http.NewRequest("GET", remote.URL, nil)
		if err := c.http.CheckRedirect(req, []*http.Request{previous}); err == nil {
			t.Error("HTTPS downgrade accepted")
		}
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer key" {
			t.Error("local auth lost")
		}
		w.Write([]byte(`{}`))
	}))
	defer local.Close()
	if _, err := NewClientWithBaseURL(local.URL, "key").GetConfig(); err != nil {
		t.Fatal(err)
	}
}

type round1Transport func(*http.Request) (*http.Response, error)

func (f round1Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRound1BrowserRejectsUnsafeTargets(t *testing.T) {
	// An empty PATH guarantees that no OS handler can execute, even on the RED path.
	t.Setenv("PATH", "")
	for _, target := range []string{"file:///etc/passwd", "custom:run", "/some/path", "-option", "https:opaque", "http://example.com", "https:///missing-host"} {
		if err := openBrowser(target); err == nil || !strings.Contains(err.Error(), "unsafe browser URL") {
			t.Errorf("target %q: want boundary rejection, got %v", target, err)
		}
	}
}
