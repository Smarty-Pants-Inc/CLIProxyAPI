package logging

import (
	"strings"
	"testing"
)

// Data safety: strict upstream redaction must run after escape decoding but
// before truncation or ordinary redaction can obscure a scheme/token shape.
func TestSafeUpstreamDiagnosticForLog(t *testing.T) {
	for _, secret := range []string{
		"https://billing.internal.example/v1/accounts/acct_other_482",
		"scheme+transport://billing.internal.example/secret",
		strings.Repeat("a", 40) + "://billing.internal.example/secret",
		strings.Repeat("a", 40) + `%253A%252F%252Fbilling.internal.example%252Fsecret`,
		`https:\/\/billing.internal.example\/secret`,
		"acct_other_482", "org_other", "proj_other", "sk-private",
		"0123456789abcdef0123", "AbCdEf0123456789+/abC", strings.Repeat("a", 32),
		"privateAddressLongerThan20@example.com", "acct_other_482@example.com",
	} {
		t.Run(secret, func(t *testing.T) {
			if got := SafeUpstreamDiagnosticForLog("before " + secret + " after"); got != "before [REDACTED] after" {
				t.Fatalf("private upstream diagnostic not fully redacted: %q", got)
			}
		})
	}
	secret := "0123456789abcdef0123"
	got := SafeUpstreamDiagnosticForLog(strings.Repeat("x ", 145) + secret)
	if strings.Contains(got, "01234") || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("truncation exposed the beginning of a key: %q", got)
	}
}
