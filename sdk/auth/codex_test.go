package auth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexAuthenticatorLoginEndToEndCallbackValidation(t *testing.T) {
	var exchanges atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("token method = %s, want POST", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse token form: %v", err)
		}
		if r.Form.Get("code") != "auth-code" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code_verifier") == "" {
			t.Errorf("unexpected token exchange form: %v", r.Form)
		}
		claims, _ := json.Marshal(map[string]any{
			"email":                       "codex-test@example.com",
			"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "account-test", "chatgpt_plan_type": "plus"},
		})
		idToken := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claims) + ".signature"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "test-access", "refresh_token": "test-refresh",
			"id_token": idToken, "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	defer tokenServer.Close()

	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()

	authenticator := NewCodexAuthenticator()
	authenticator.HTTPClient = tokenServer.Client()
	authenticator.TokenURL = tokenServer.URL
	defer authenticator.HTTPClient.CloseIdleConnections()

	// Capture the URL actually printed by the no-browser native login path,
	// rather than injecting state or constructing the callback server ourselves.
	oldStdout := os.Stdout
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = stdoutWriter
	defer func() {
		os.Stdout = oldStdout
		_ = stdoutWriter.Close()
		_ = stdoutReader.Close()
	}()
	lines := make(chan string, 32)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(stdoutReader)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
	}()

	type outcome struct {
		auth *coreauth.Auth
		err  error
	}
	done := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		record, loginErr := authenticator.Login(ctx, &config.Config{}, &LoginOptions{NoBrowser: true, CallbackPort: port})
		done <- outcome{record, loginErr}
	}()

	var authURL string
	deadline := time.After(3 * time.Second)
	for authURL == "" {
		select {
		case line, ok := <-lines:
			if !ok {
				t.Fatal("login output closed before auth URL")
			}
			if strings.HasPrefix(line, "https://auth.openai.com/oauth/authorize?") {
				authURL = line
			}
		case got := <-done:
			t.Fatalf("login ended before printing auth URL: %v", got.err)
		case <-deadline:
			t.Fatal("timed out waiting for printed auth URL")
		}
	}
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsedURL.Query().Get("state")
	if state == "" {
		t.Fatal("printed auth URL has no state")
	}

	client := &http.Client{
		Timeout:       2 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	callbackURL := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/auth/callback"
	// Ensure a failed assertion still releases the pending login and its listener.
	defer func() {
		resp, _ := client.Get(callbackURL + "?code=auth-code&state=" + url.QueryEscape(state))
		if resp != nil {
			_ = resp.Body.Close()
		}
	}()
	for _, query := range []string{"", "code=wrong", "code=wrong&state=wrong", "error=access_denied", "error=access_denied&state=wrong"} {
		resp, requestErr := client.Get(callbackURL + "?" + query)
		if requestErr != nil {
			t.Fatalf("invalid callback %q: %v", query, requestErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("invalid callback %q status = %d, want 404", query, resp.StatusCode)
		}
		t.Logf("unrelated callback %q: 404", query)
	}
	select {
	case got := <-done:
		t.Fatalf("login ended after invalid callback: %v", got.err)
	case <-time.After(100 * time.Millisecond):
	}
	if exchanges.Load() != 0 {
		t.Fatal("unrelated callback triggered token exchange")
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
			continue
		}
		address := net.JoinHostPort(ipNet.IP.String(), strconv.Itoa(port))
		conn, dialErr := net.DialTimeout("tcp4", address, time.Second)
		if dialErr == nil {
			_ = conn.Close()
			t.Fatalf("non-loopback %s accepted a connection", address)
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			t.Fatalf("non-loopback %s: %v, want connection refused", address, dialErr)
		}
		checked++
		t.Logf("non-loopback %s: connection refused", address)
	}
	if checked == 0 {
		t.Fatal("no non-loopback IPv4 address available to prove listener isolation")
	}

	resp, err := client.Get(callbackURL + "?code=auth-code&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("valid callback status = %d, want 302", resp.StatusCode)
	}
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("login failed: %v", got.err)
		}
		if got.auth == nil || got.auth.Provider != "codex" || got.auth.Metadata["email"] != "codex-test@example.com" {
			t.Fatalf("login returned unexpected auth: %+v", got.auth)
		}
		if exchanges.Load() != 1 {
			t.Fatalf("token exchanges = %d, want 1", exchanges.Load())
		}
		t.Log("correct printed state: 302; login completed with Codex auth record")
	case <-ctx.Done():
		t.Fatal("timed out completing login after valid callback")
	}
}
