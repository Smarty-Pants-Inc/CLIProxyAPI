package helps

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/tidwall/gjson"
)

// Data safety: upstream prose is never public, and server-only diagnostics must
// redact private URLs, identities and opaque keys even outside named fields.
func TestStreamErrorPrivateDiagnostics(t *testing.T) {
	hook := logtest.NewGlobal()
	defer hook.Reset()
	for _, private := range []string{
		"https://billing.internal.example/v1/accounts/acct_other_482",
		"custom+transport://private.internal/secret",
		strings.Repeat("a", 40) + "://billing.internal.example/secret",
		strings.Repeat("a", 40) + "%3A%2F%2Fbilling.internal.example%2Fsecret",
		"acct_other_482", "org_private_123", "sk-private", "proj_private_123",
		"0123456789abcdef0123", "ABCdef0123456789+/abC", "abc_def-0123456789xyz",
		"owner@example.com", "aVeryLongPrivateEmailAddress@example.com",
		`https%3A%2F%2Fbilling.internal.example%2Fv1%2Facct_other_482`,
	} {
		t.Run(private, func(t *testing.T) {
			hook.Reset()
			payload, errMarshal := json.Marshal(map[string]any{"error": map[string]any{
				"type": "server_error", "code": "server_error", "message": "diagnostic before " + private + " after",
			}})
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			var progress StreamProgress
			err := progress.UpstreamError(context.Background(), "fixture", "fixture", "label", 200, payload, nil)
			if got := gjson.Get(err.Error(), "error.message").String(); got != "upstream server error: server_error" {
				t.Fatalf("public message contains upstream prose: %q", got)
			}
			entries := hook.AllEntries()
			if len(entries) != 1 {
				t.Fatalf("want one warn, got %d", len(entries))
			}
			got, ok := entries[0].Data["message"].(string)
			if !ok || got != "diagnostic before [REDACTED] after" {
				t.Fatalf("lost safe diagnostic context or leaked private prose: %q", got)
			}
		})
	}
}
