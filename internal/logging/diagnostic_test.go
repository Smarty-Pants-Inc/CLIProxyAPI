package logging

import (
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestSafeDiagnosticForLogPreservesAccessTokenExpiredAndRedactsCredentials(t *testing.T) {
	diagnostic := "access token expired\n" +
		`access_token=access-secret refresh token: refresh-secret Authorization=Bearer bearer-secret ` +
		`Post "https://user:password@oauth.example/token?access_token=query-secret" via socks5://proxy-user:proxy-password@127.0.0.1:1080`

	got := SafeDiagnosticForLog(diagnostic)
	if !strings.Contains(got, "access token expired") {
		t.Fatalf("safe diagnostic lost access-token-expired signal: %q", got)
	}
	for _, secret := range []string{"access-secret", "refresh-secret", "bearer-secret", "query-secret", "user:password", "proxy-user", "proxy-password"} {
		if strings.Contains(got, secret) {
			t.Fatalf("safe diagnostic leaked %q: %q", secret, got)
		}
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("safe diagnostic retained a line break: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("safe diagnostic did not mark redacted values: %q", got)
	}
}

func TestSafeDiagnosticForLogKeepsPlainAccessTokenExpiredMessage(t *testing.T) {
	const diagnostic = "access token expired"
	if got := SafeDiagnosticForLog(diagnostic); got != diagnostic {
		t.Fatalf("SafeDiagnosticForLog() = %q, want %q", got, diagnostic)
	}
}

func TestSafeDiagnosticForLogBoundsLargeMessageAndRetainsTrailingSignal(t *testing.T) {
	diagnostic := strings.Repeat("upstream context ", 1000) + "access token expired\nforged log line"
	got := SafeDiagnosticForLog(diagnostic)
	if len([]rune(got)) > diagnosticLogRuneLimit+3 {
		t.Fatalf("safe diagnostic length = %d, want at most %d", len([]rune(got)), diagnosticLogRuneLimit+3)
	}
	if !strings.Contains(got, "access token expired") {
		t.Fatalf("safe diagnostic lost trailing access-token-expired signal: %q", got)
	}
	if strings.ContainsAny(got, "\r\n") {
		t.Fatalf("safe diagnostic retained a line break: %q", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("safe diagnostic did not indicate truncation: %q", got)
	}
}

func TestSafeDiagnosticForLogBoundsLargeGenericMessage(t *testing.T) {
	got := SafeDiagnosticForLog(strings.Repeat("xy ", 300))
	if len([]rune(got)) != diagnosticLogRuneLimit+3 || !strings.HasSuffix(got, "...") {
		t.Fatalf("safe generic diagnostic length = %d, want %d with ellipsis", len([]rune(got)), diagnosticLogRuneLimit+3)
	}
}

func TestSafeErrorDiagnosticExtractsOnlyAllowlistedSignals(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantParts []string
	}{
		{name: "EOF", err: io.EOF, wantParts: []string{"EOF"}},
		{name: "SOCKS refused", err: errors.New("socks connect with unlabeled-secret: connection refused"), wantParts: []string{"proxy=socks", "connection_refused"}},
		{name: "OAuth response", err: errors.New(`upstream status 400 error="invalid_request" request_id="req-123" unlabeled-secret`), wantParts: []string{"status=400"}},
		{name: "unknown", err: errors.New("unlabeled-secret")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SafeErrorDiagnostic(tt.err)
			for _, want := range tt.wantParts {
				if !strings.Contains(got, want) {
					t.Fatalf("SafeErrorDiagnostic() = %q, want %q", got, want)
				}
			}
			if strings.Contains(got, "unlabeled-secret") {
				t.Fatalf("SafeErrorDiagnostic() leaked arbitrary detail: %q", got)
			}
		})
	}
}

func TestSafeErrorDiagnosticDoesNotExtractURLQueryValues(t *testing.T) {
	err := &url.Error{
		Op:  "Post",
		URL: "https://oauth.example/token?code=oauth-secret&error=error-secret&request_id=request-secret",
		Err: io.EOF,
	}

	got := SafeErrorDiagnostic(err)
	if !strings.Contains(got, "EOF") {
		t.Fatalf("SafeErrorDiagnostic() = %q, want EOF signal", got)
	}
	for _, secret := range []string{"oauth-secret", "error-secret", "request-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("SafeErrorDiagnostic() leaked %q: %q", secret, got)
		}
	}
	for _, dynamicField := range []string{"oauth_error=", "request_id="} {
		if strings.Contains(got, dynamicField) {
			t.Fatalf("SafeErrorDiagnostic() extracted dynamic field %q: %q", dynamicField, got)
		}
	}
}

// smarty-dev#5423 security round 1: encoded secrets are normalized before matching.
func TestSafeDiagnosticForLogRedactsEncodedSecrets(t *testing.T) {
	const base64Token = "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTBhYmNkZWY="
	cases := []struct {
		name    string
		message string
		secrets []string
	}{
		{"url-encoded email", "quota exceeded for user=person%40example.com", []string{"person", "example.com"}},
		{"double url-encoded email", "quota exceeded for person%2540example.com", []string{"person", "example.com"}},
		{"url-encoded key separator", "GET /v1/models?api_key%3Dsk-live%2BAbC%2F123 failed", []string{"sk-live", "AbC"}},
		{"json-escaped email", `{"error":{"message":"limit for person\u0040example.com","email":\"other@example.org\"}}`, []string{"person", "other@example.org", "example.org"}},
		{"base64 token in query field", "upstream rejected https://api.example/v1?q=1&state=" + base64Token + "&x=y", []string{base64Token, "QWxhZGRpbjpvcGVu"}},
		{"base64 key in key field", "invalid key=" + "AIzaSyD-abcdefghijklmnop0123", []string{"AIzaSyD-abcdefghijklmnop0123"}},
		// security round 2: single-case opaque values in an unrecognized field.
		{"lower-case+digits 40-char token", "upstream rejected nonce=k7q2zx9m4tw8vr3ny6pl1hs5gj0cbu2xq8wz4kmt", []string{"k7q2zx9m4tw8vr3ny6pl1hs5gj0cbu2xq8wz4kmt", "k7q2zx9m"}},
		{"upper-case base64 token", "upstream rejected nonce=QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", []string{"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo"}},
		{"base64url with - and _", "upstream rejected nonce=Zm9vYmFy_YmF6cXV4-cXV1eF9nYXJwbHk_d2FsZG8", []string{"Zm9vYmFy", "cXV1eF9nYXJwbHk", "d2FsZG8"}},
		{"lower-case base64url pieces", "upstream rejected nonce=abcdefghijklmnopq-rstuvwxyz0123456789", []string{"abcdefghijklmnopq", "rstuvwxyz0123456789"}},
	}
	for _, tc := range cases {
		got := SafeDiagnosticForLog(tc.message)
		for _, secret := range tc.secrets {
			if strings.Contains(got, secret) {
				t.Errorf("%s: leaked %q: %q", tc.name, secret, got)
			}
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("%s: no redaction marker: %q", tc.name, got)
		}
	}
}

func TestSafeDiagnosticForLogKeepsBenignLineReadable(t *testing.T) {
	const benign = "429 Too Many Requests: rate_limit_exceeded for model gpt-6 at /v1/responses/compact, retry after 30s (request 0123456789abcdef0123456789abcdef) " +
		"path /v1/projects/my-project/locations/us-central1/publishers/google/models req_0123456789ABCDEF0123456789abcdef model claude-sonnet-4-5-20250929-thinking"
	if got := SafeDiagnosticForLog(benign); got != benign {
		t.Fatalf("benign diagnostic changed:\n got %q\nwant %q", got, benign)
	}
}
